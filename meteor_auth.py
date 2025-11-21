# meteor_auth.py

"""
Meteor-Auth: Device-Bound Quantum-Resistant Authentication

The world's first passwordless authentication system
combining device binding with post-quantum cryptography.

License: MIT
"""

import hashlib
import uuid
import platform
import secrets
from typing import Optional, Tuple, Dict
from meteor_nc_kdf import MeteorNC_KDF
from meteor_protocol import MeteorNode


class MeteorAuth:
    """
    Meteor-Auth Core
    
    Features:
    - Device-bound keys
    - Passwordless authentication
    - Quantum-resistant
    - Zero server trust
    - Full P2P integration
    
    Usage:
        # Client
        auth = MeteorAuth()
        user_seed = auth.generate_seed()  # Save this!
        session = auth.login(user_seed)
        
        # Server
        server = MeteorAuthServer()
        is_valid = server.authenticate(challenge_response)
    """
    
    def __init__(self, security_level: int = 256):
        """
        Initialize Meteor-Auth
        
        Args:
            security_level: 128, 256, 512, 1024, 2048
        """
        self.security_level = security_level
        self.n = security_level
        self.m = self._get_m(security_level)
    
    def _get_m(self, n: int) -> int:
        """Get layer count for security level"""
        if n == 128: return 8
        elif n == 256: return 10
        elif n == 512: return 12
        elif n == 1024: return 14
        elif n == 2048: return 16
        else: return 10
    
    def get_device_fingerprint(self) -> bytes:
        """
        Generate device fingerprint
        
        Components:
        - MAC address
        - Platform (OS, machine, version)
        - Processor info
        
        Returns:
            32-byte device fingerprint
        """
        # MAC address
        mac = uuid.getnode()
        
        # Platform info
        system = platform.system()
        machine = platform.machine()
        version = platform.version()
        processor = platform.processor()
        
        # Combine
        device_info = f"{mac}|{system}|{machine}|{version}|{processor}"
        
        # Hash to 32 bytes
        fingerprint = hashlib.sha256(device_info.encode('utf-8')).digest()
        
        return fingerprint
    
    def generate_seed(self) -> bytes:
        """
        Generate user seed (Knowledge factor)
        
        ⚠️ SAVE THIS SECURELY!
        - Print as QR code
        - Store in password manager
        - Write on paper (secure location)
        
        Returns:
            32-byte user seed
        """
        return secrets.token_bytes(32)
    
    def create_device_bound_seed(self, user_seed: bytes) -> bytes:
        """
        Create device-bound seed
        
        Combines:
        - User seed (Knowledge: what you know)
        - Device fingerprint (Possession: what you have)
        
        Args:
            user_seed: 32-byte user seed
        
        Returns:
            32-byte device-bound seed
        """
        device_fp = self.get_device_fingerprint()
        
        # HKDF-style derivation
        combined = user_seed + device_fp
        device_bound = hashlib.sha256(combined).digest()
        
        return device_bound
    
    def login(self, user_seed: bytes, node_name: Optional[str] = None) -> MeteorNode:
        """
        Login (Key expansion + P2P node creation)
        
        Args:
            user_seed: 32-byte user seed
            node_name: Optional node name (default: "Client")
        
        Returns:
            MeteorNode with device-bound keys
        """
        # Device-bound seed
        auth_seed = self.create_device_bound_seed(user_seed)
        
        # Create Meteor node with device-bound keys
        node = MeteorNode(node_name or "Client")
        
        # Expand keys with device-bound seed
        node.crypto = MeteorNC_KDF(
            n=self.n,
            m=self.m,
            seed=auth_seed
        )
        node.crypto.expand_keys()
        
        # Set Meteor ID
        node.meteor_id = self.get_meteor_id(user_seed)
        
        return node
    
    def get_meteor_id(self, user_seed: bytes) -> bytes:
        """
        Get Meteor ID (public identifier)
        
        This is the user's public identity in the Meteor network.
        It's derived from device-bound seed, so it's unique per device.
        
        Args:
            user_seed: 32-byte user seed
        
        Returns:
            32-byte Meteor ID
        
        Note:
            - Same user_seed on different devices = different IDs
            - This enables device-bound authentication
            - Safe to share publicly (like username)
        """
        # Generate device-bound seed
        device_seed = self.create_device_bound_seed(user_seed)
        
        # Derive Meteor ID (public identifier)
        # Using domain separation: "METEOR_ID_v1"
        meteor_id = hashlib.sha256(b"METEOR_ID_v1" + device_seed).digest()
        
        return meteor_id
    
    def export_qr_data(self, user_seed: bytes) -> str:
        """
        Export seed as QR-compatible string
        
        Args:
            user_seed: 32-byte user seed
        
        Returns:
            Hex-encoded seed
        """
        return user_seed.hex()
    
    def import_qr_data(self, qr_data: str) -> bytes:
        """
        Import seed from QR code
        
        Args:
            qr_data: Hex-encoded seed
        
        Returns:
            32-byte user seed
        """
        return bytes.fromhex(qr_data)


class MeteorAuthServer:
    """
    Meteor-Auth Server
    
    Features:
    - Zero password storage
    - Zero personal info storage
    - Only stores 32-byte Meteor IDs
    - Full P2P integration
    - Challenge-response authentication
    
    Usage:
        server = MeteorAuthServer()
        
        # Registration
        token = server.register(meteor_id)
        
        # Authentication
        is_valid = server.authenticate(token, encrypted_response)
    """
    
    def __init__(self, node_name: str = "AuthServer"):
        """
        Initialize server
        
        Args:
            node_name: Server node name
        """
        self.node = MeteorNode(node_name)
        self.users: Dict[str, dict] = {}  # token -> user_info
        self.challenges: Dict[str, bytes] = {}  # token -> current_challenge
    
    def register(self, meteor_id: bytes, metadata: dict = None) -> str:
        """
        Register user
        
        Args:
            meteor_id: 32-byte Meteor ID
            metadata: Optional metadata (username, etc.)
        
        Returns:
            User token (hex)
        """
        import time
        
        # Generate unique token
        token = hashlib.sha256(meteor_id + secrets.token_bytes(16)).hexdigest()
        
        # Store user info (ID only, no password!)
        self.users[token] = {
            'meteor_id': meteor_id,
            'metadata': metadata or {},
            'registered_at': time.time()
        }
        
        # Add as peer in P2P network
        self.node.add_peer(token, meteor_id)
        
        print(f"[{self.node.name}] Registered user: {token[:32]}...")
        print(f"  Meteor ID: {meteor_id.hex()[:32]}...")
        
        return token
    
    def create_challenge(self, token: str) -> bytes:
        """
        Create authentication challenge (plaintext)
        
        Args:
            token: User token
        
        Returns:
            challenge (plaintext, 32 bytes)
        """
        if token not in self.users:
            raise ValueError(f"Unknown token: {token}")
        
        # Generate random challenge
        challenge = secrets.token_bytes(32)
        
        # Store for verification
        self.challenges[token] = challenge
        
        print(f"[{self.node.name}] Challenge created: {challenge.hex()[:32]}...")
        
        # Return plaintext (client will encrypt)
        return challenge
    
    def authenticate(self, token: str, encrypted_response: bytes) -> bool:
        """
        Authenticate user via challenge-response
        
        Flow:
        1. Server creates challenge (plaintext)
        2. Client encrypts challenge with their key
        3. Server decrypts with peer key and verifies
        
        Args:
            token: User token
            encrypted_response: Client's encrypted challenge
        
        Returns:
            True if valid, False otherwise
        """
        if token not in self.users:
            print(f"[Auth Failed] Unknown token")
            return False
        
        if token not in self.challenges:
            print(f"[Auth Failed] No challenge for token")
            return False
        
        try:
            # Decrypt response using P2P
            # (Client encrypted with their key, server has peer key)
            decrypted = self.node.receive(encrypted_response)
            
            # Verify it matches the challenge
            expected = self.challenges[token]
            
            if decrypted == expected:
                print(f"[{self.node.name}] ✅ Authentication SUCCESS for {token[:16]}...")
                # Clean up challenge
                del self.challenges[token]
                return True
            else:
                print(f"[Auth Failed] Challenge mismatch")
                print(f"  Expected: {expected.hex()[:32]}...")
                print(f"  Got: {decrypted.hex()[:32]}...")
                return False
                
        except Exception as e:
            print(f"[Auth Failed] Decryption error: {e}")
            return False
    
    def get_user_info(self, token: str) -> Optional[dict]:
        """
        Get user metadata
        
        Args:
            token: User token
        
        Returns:
            User info dict or None
        """
        return self.users.get(token)
    
    def revoke(self, token: str) -> bool:
        """
        Revoke user token
        
        Args:
            token: User token
        
        Returns:
            True if revoked
        """
        if token in self.users:
            # Remove from users
            del self.users[token]
            
            # Remove peer
            self.node.remove_peer(token)
            
            # Remove any pending challenges
            if token in self.challenges:
                del self.challenges[token]
            
            print(f"[Revoked] Token {token[:16]}...")
            return True
        
        return False


# ==================================================================
# The Secret: Holographic Cryptography
# ==================================================================
# Meteor-Auth builds on Meteor-NC's holographic correspondence
# principles (AdS/CFT) to create the first quantum-resistant
# device-bound authentication system.
#
# Device binding = "bulk structure" tied to physical hardware
# Authentication = Perfect reconstruction with both factors
#
# Zero trust: Server never stores passwords or personal info
# Zero passwords: QR code + device = authentication
#
# Full P2P integration enables:
# - Serverless authentication meshes
# - Decentralized identity verification
# - Web 4.0 authentication primitives
#
# Welcome to Web 4.0. 🌌
# ==================================================================
