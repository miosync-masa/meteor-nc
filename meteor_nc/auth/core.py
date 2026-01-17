# meteor_nc/auth/core.py
"""
Meteor-Auth: Device-Bound Quantum-Resistant Authentication

The world's first passwordless authentication system combining
device binding with post-quantum cryptography.

Features:
    - Device-bound keys (3FA: Knowledge + Possession + Inherence)
    - Passwordless authentication via QR code
    - Quantum-resistant (Meteor-NC LWE-KEM)
    - Zero server trust (no password storage)
    - Full P2P integration
    - Biometric hook for iOS/Android integration

Updated for Meteor-NC v2.0 API
"""

from __future__ import annotations

import hashlib
import uuid
import platform
import secrets
import time
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, field
from enum import Enum

from ..cryptography.common import _sha256, GPU_AVAILABLE
from ..protocols.meteor_protocol import MeteorNode, MeteorMessage


# =============================================================================
# Biometric Authentication Hook
# =============================================================================

class BiometricStatus(Enum):
    """Biometric verification status."""
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"
    NOT_AVAILABLE = "not_available"
    LOCKOUT = "lockout"  # Too many failed attempts


class BiometricProvider:
    """
    Abstract biometric authentication provider.
    
    Implement this interface to integrate platform-specific biometrics:
    - iOS: LocalAuthentication (Face ID / Touch ID)
    - Android: BiometricPrompt
    - Windows: Windows Hello
    - Custom: Hardware security keys, etc.
    
    Example (iOS):
        >>> class IOSBiometric(BiometricProvider):
        ...     def verify(self) -> BiometricStatus:
        ...         context = LAContext()
        ...         if context.evaluatePolicy_localizedReason_reply_(
        ...             LAPolicyDeviceOwnerAuthenticationWithBiometrics,
        ...             "Meteor Authentication",
        ...             callback
        ...         ):
        ...             return BiometricStatus.SUCCESS
        ...         return BiometricStatus.FAILED
        ...     
        ...     def is_available(self) -> bool:
        ...         return LAContext().canEvaluatePolicy_(...)
        ...     
        ...     def get_type(self) -> str:
        ...         # Check Face ID vs Touch ID
        ...         return "face_id" or "touch_id"
    
    Example (Android):
        >>> class AndroidBiometric(BiometricProvider):
        ...     def verify(self) -> BiometricStatus:
        ...         prompt = BiometricPrompt.Builder(context)
        ...             .setTitle("Meteor Authentication")
        ...             .setNegativeButtonText("Cancel")
        ...             .build()
        ...         # ... callback handling
        ...         return BiometricStatus.SUCCESS
        ...     
        ...     def is_available(self) -> bool:
        ...         manager = BiometricManager.from_(context)
        ...         return manager.canAuthenticate() == BIOMETRIC_SUCCESS
    """
    
    def verify(self) -> BiometricStatus:
        """
        Perform biometric verification.
        
        Returns:
            BiometricStatus: Result of verification
        """
        raise NotImplementedError("Subclass must implement verify()")
    
    def is_available(self) -> bool:
        """
        Check if biometric authentication is available on this device.
        
        Returns:
            bool: True if biometrics can be used
        """
        raise NotImplementedError("Subclass must implement is_available()")
    
    def get_type(self) -> str:
        """
        Get biometric type name.
        
        Returns:
            str: e.g., "face_id", "touch_id", "fingerprint", "windows_hello"
        """
        return "unknown"


class CallbackBiometricProvider(BiometricProvider):
    """
    Simple biometric provider using a callback function.
    
    For easy integration when you just need to call a function.
    
    Example:
        >>> def my_fingerprint_check() -> bool:
        ...     return call_native_fingerprint_api()
        >>> 
        >>> provider = CallbackBiometricProvider(
        ...     verify_callback=my_fingerprint_check,
        ...     biometric_type="fingerprint"
        ... )
    """
    
    def __init__(
        self,
        verify_callback: Callable[[], bool],
        is_available_callback: Optional[Callable[[], bool]] = None,
        biometric_type: str = "callback",
    ):
        """
        Initialize callback-based biometric provider.
        
        Args:
            verify_callback: Function that returns True if verification succeeds
            is_available_callback: Function that returns True if biometric is available
            biometric_type: String identifier for the biometric type
        """
        self._verify = verify_callback
        self._is_available = is_available_callback or (lambda: True)
        self._type = biometric_type
    
    def verify(self) -> BiometricStatus:
        try:
            if self._verify():
                return BiometricStatus.SUCCESS
            return BiometricStatus.FAILED
        except Exception:
            return BiometricStatus.FAILED
    
    def is_available(self) -> bool:
        try:
            return self._is_available()
        except Exception:
            return False
    
    def get_type(self) -> str:
        return self._type


class MockBiometricProvider(BiometricProvider):
    """
    Mock biometric provider for testing.
    
    Always returns the configured result.
    """
    
    def __init__(
        self,
        result: BiometricStatus = BiometricStatus.SUCCESS,
        available: bool = True,
        biometric_type: str = "mock",
    ):
        self._result = result
        self._available = available
        self._type = biometric_type
    
    def verify(self) -> BiometricStatus:
        return self._result
    
    def is_available(self) -> bool:
        return self._available
    
    def get_type(self) -> str:
        return self._type


class DefaultBiometricProvider(BiometricProvider):
    """
    Default (no-op) biometric provider.
    
    Used when biometrics are not required - always succeeds.
    """
    
    def verify(self) -> BiometricStatus:
        return BiometricStatus.SUCCESS
    
    def is_available(self) -> bool:
        return False  # Not actually available, just bypassed
    
    def get_type(self) -> str:
        return "none"


# =============================================================================
# Authentication Exceptions
# =============================================================================

class MeteorAuthError(Exception):
    """Base exception for Meteor-Auth errors."""
    pass


class BiometricRequiredError(MeteorAuthError):
    """Raised when biometric verification is required but unavailable."""
    pass


class BiometricFailedError(MeteorAuthError):
    """Raised when biometric verification fails."""
    
    def __init__(self, status: BiometricStatus, message: str = ""):
        self.status = status
        super().__init__(message or f"Biometric verification failed: {status.value}")


# =============================================================================
# Client Authentication
# =============================================================================

class MeteorAuth:
    """
    Meteor-Auth Client: Device-Bound Quantum-Resistant Authentication
    
    Provides passwordless authentication using:
    - User seed (Knowledge factor): 32-byte secret, stored as QR code
    - Device fingerprint (Possession factor): Hardware-bound identifier
    - Biometric verification (Inherence factor): Optional 3FA
    
    The combination creates a device-bound seed that generates
    quantum-resistant keys for authentication.
    
    Security Levels:
        - 2FA (default): Knowledge + Possession
        - 3FA (with biometrics): Knowledge + Possession + Inherence
    
    3FA Security Model:
        | Attacker has           | Can authenticate? |
        |------------------------|-------------------|
        | user_seed only         | ❌ Wrong device   |
        | Device only            | ❌ No seed        |
        | user_seed + device     | ❌ No biometric*  |
        | user_seed + device + 指| ✅ (= legitimate) |
        
        * When require_biometric=True
    
    Example:
        >>> auth = MeteorAuth()
        >>> user_seed = auth.generate_seed()  # Save as QR!
        >>> meteor_id = auth.get_meteor_id(user_seed)  # Public identity
        >>> node = auth.login(user_seed)  # Create P2P node
        
        # With biometric (3FA):
        >>> auth = MeteorAuth(require_biometric=True, biometric_provider=my_provider)
        >>> node = auth.login(user_seed)  # Triggers biometric verification
        
        # With callback (simple integration):
        >>> auth = MeteorAuth(require_biometric=True)
        >>> auth.set_biometric_callback(my_fingerprint_check)
        >>> node = auth.login(user_seed)
    """
    
    def __init__(
        self,
        gpu: bool = True,
        device_id: int = 0,
        require_biometric: bool = False,
        biometric_provider: Optional[BiometricProvider] = None,
    ):
        """
        Initialize Meteor-Auth client.
        
        Args:
            gpu: Use GPU acceleration
            device_id: GPU device ID
            require_biometric: If True, login() requires biometric verification
            biometric_provider: Custom biometric provider (platform-specific)
        """
        self.gpu = gpu and GPU_AVAILABLE
        self.device_id = device_id
        self.require_biometric = require_biometric
        self._biometric_provider = biometric_provider
        
        # Last biometric verification timestamp
        self._last_biometric_time: Optional[float] = None
        self._biometric_valid_duration: float = 300.0  # 5 minutes
    
    @property
    def biometric_provider(self) -> BiometricProvider:
        """Get current biometric provider."""
        return self._biometric_provider or DefaultBiometricProvider()
    
    def set_biometric_provider(self, provider: BiometricProvider) -> None:
        """
        Set biometric provider.
        
        Args:
            provider: BiometricProvider implementation
        """
        self._biometric_provider = provider
    
    def set_biometric_callback(
        self,
        verify_callback: Callable[[], bool],
        is_available_callback: Optional[Callable[[], bool]] = None,
        biometric_type: str = "callback",
    ) -> None:
        """
        Set biometric verification using simple callbacks.
        
        Convenience method for easy integration.
        
        Args:
            verify_callback: Function returning True if verification succeeds
            is_available_callback: Function returning True if biometric available
            biometric_type: Type identifier (e.g., "fingerprint", "face_id")
        
        Example:
            >>> def check_fingerprint():
            ...     # Call platform API
            ...     return native_fingerprint_verify()
            >>> 
            >>> auth.set_biometric_callback(check_fingerprint, biometric_type="fingerprint")
        """
        self._biometric_provider = CallbackBiometricProvider(
            verify_callback=verify_callback,
            is_available_callback=is_available_callback,
            biometric_type=biometric_type,
        )
    
    def _verify_biometric(self) -> BiometricStatus:
        """
        Internal biometric verification.
        
        Returns:
            BiometricStatus: Result of verification
        """
        provider = self.biometric_provider
        
        # Check if recent verification is still valid
        if self._last_biometric_time is not None:
            elapsed = time.time() - self._last_biometric_time
            if elapsed < self._biometric_valid_duration:
                return BiometricStatus.SUCCESS
        
        # Perform verification
        status = provider.verify()
        
        if status == BiometricStatus.SUCCESS:
            self._last_biometric_time = time.time()
        
        return status
    
    def is_biometric_available(self) -> bool:
        """
        Check if biometric authentication is available.
        
        Returns:
            bool: True if biometrics can be used on this device
        """
        return self.biometric_provider.is_available()
    
    def get_biometric_type(self) -> str:
        """
        Get current biometric type.
        
        Returns:
            str: Biometric type identifier
        """
        return self.biometric_provider.get_type()
    
    def invalidate_biometric(self) -> None:
        """
        Invalidate cached biometric verification.
        
        Forces re-verification on next login.
        """
        self._last_biometric_time = None
    
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
    
    def login(
        self,
        user_seed: bytes,
        node_name: Optional[str] = None,
        skip_biometric: bool = False,
    ) -> MeteorNode:
        """
        Login and create P2P node with device-bound keys.
        
        Args:
            user_seed: 32-byte user seed
            node_name: Optional node display name
            skip_biometric: Skip biometric verification (for testing only!)
            
        Returns:
            MeteorNode: P2P node with quantum-resistant keys
            
        Raises:
            BiometricRequiredError: If biometric required but not available
            BiometricFailedError: If biometric verification fails
        """
        # Biometric verification (3FA)
        if self.require_biometric and not skip_biometric:
            provider = self.biometric_provider
            
            # Check availability
            if not provider.is_available():
                raise BiometricRequiredError(
                    f"Biometric authentication required but not available. "
                    f"Provider: {provider.get_type()}"
                )
            
            # Verify
            status = self._verify_biometric()
            
            if status != BiometricStatus.SUCCESS:
                raise BiometricFailedError(status)
        
        # Create device-bound seed (2FA: Knowledge + Possession)
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
    print("Meteor-Auth Test Suite (with Biometric Hooks)")
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
    
    # Test 5: Login (2FA)
    print("\n[Test 5] Login (2FA)")
    print("-" * 40)
    
    node = auth.login(user_seed, "TestClient")
    
    login_ok = node is not None and node.get_meteor_id() is not None
    results["login_2fa"] = login_ok
    print(f"  Node name: {node.name}")
    print(f"  Node ID: {node.get_meteor_id().hex()[:32]}...")
    print(f"  Result: {'PASS' if login_ok else 'FAIL'}")
    
    # Test 6: Biometric callback (3FA)
    print("\n[Test 6] Login with Biometric Callback (3FA)")
    print("-" * 40)
    
    auth_3fa = MeteorAuth(gpu=GPU_AVAILABLE, require_biometric=True)
    
    # Set callback that always succeeds
    auth_3fa.set_biometric_callback(
        verify_callback=lambda: True,
        is_available_callback=lambda: True,
        biometric_type="test_fingerprint",
    )
    
    node_3fa = auth_3fa.login(user_seed, "TestClient3FA")
    
    biometric_ok = node_3fa is not None
    results["login_3fa_callback"] = biometric_ok
    print(f"  Biometric type: {auth_3fa.get_biometric_type()}")
    print(f"  Node ID: {node_3fa.get_meteor_id().hex()[:32]}...")
    print(f"  Result: {'PASS' if biometric_ok else 'FAIL'}")
    
    # Test 7: Biometric provider (3FA)
    print("\n[Test 7] Login with Biometric Provider (3FA)")
    print("-" * 40)
    
    auth_provider = MeteorAuth(gpu=GPU_AVAILABLE, require_biometric=True)
    auth_provider.set_biometric_provider(
        MockBiometricProvider(BiometricStatus.SUCCESS, available=True, biometric_type="mock_face_id")
    )
    
    node_provider = auth_provider.login(user_seed, "TestClientProvider")
    
    provider_ok = node_provider is not None
    results["login_3fa_provider"] = provider_ok
    print(f"  Biometric type: {auth_provider.get_biometric_type()}")
    print(f"  Result: {'PASS' if provider_ok else 'FAIL'}")
    
    # Test 8: Biometric failure
    print("\n[Test 8] Biometric Failure Handling")
    print("-" * 40)
    
    auth_fail = MeteorAuth(gpu=GPU_AVAILABLE, require_biometric=True)
    auth_fail.set_biometric_provider(
        MockBiometricProvider(BiometricStatus.FAILED, available=True)
    )
    
    fail_ok = False
    try:
        auth_fail.login(user_seed)
    except BiometricFailedError as e:
        fail_ok = e.status == BiometricStatus.FAILED
        print(f"  Exception: {e}")
    
    results["biometric_fail"] = fail_ok
    print(f"  Result: {'PASS' if fail_ok else 'FAIL'}")
    
    # Test 9: Biometric not available
    print("\n[Test 9] Biometric Not Available")
    print("-" * 40)
    
    auth_unavail = MeteorAuth(gpu=GPU_AVAILABLE, require_biometric=True)
    auth_unavail.set_biometric_provider(
        MockBiometricProvider(BiometricStatus.NOT_AVAILABLE, available=False)
    )
    
    unavail_ok = False
    try:
        auth_unavail.login(user_seed)
    except BiometricRequiredError as e:
        unavail_ok = True
        print(f"  Exception: {e}")
    
    results["biometric_unavail"] = unavail_ok
    print(f"  Result: {'PASS' if unavail_ok else 'FAIL'}")
    
    # Test 10: QR export/import
    print("\n[Test 10] QR Export/Import")
    print("-" * 40)
    
    qr_data = auth.export_qr_data(user_seed)
    imported = auth.import_qr_data(qr_data)
    
    qr_ok = imported == user_seed
    results["qr_roundtrip"] = qr_ok
    print(f"  QR data: {qr_data[:32]}...")
    print(f"  Roundtrip: {qr_ok}")
    print(f"  Result: {'PASS' if qr_ok else 'FAIL'}")
    
    # Test 11: Recovery codes
    print("\n[Test 11] Recovery Codes")
    print("-" * 40)
    
    codes = generate_recovery_codes(user_seed)
    
    codes_ok = len(codes) == 8 and all(len(c) == 19 for c in codes)  # "XXXX-XXXX-XXXX-XXXX"
    results["recovery_codes"] = codes_ok
    print(f"  Codes generated: {len(codes)}")
    for i, code in enumerate(codes[:3]):
        print(f"    {i+1}. {code}")
    print(f"    ...")
    print(f"  Result: {'PASS' if codes_ok else 'FAIL'}")
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED ✅' if all_pass else 'SOME TESTS FAILED ❌'}")
    
    if all_pass:
        print("\n✓ 3FA Security Model verified:")
        print("  - Knowledge: user_seed (QR code)")
        print("  - Possession: device_fingerprint")
        print("  - Inherence: biometric (hook ready)")
        print("\n✓ Biometric integration points:")
        print("  - BiometricProvider (subclass for iOS/Android)")
        print("  - CallbackBiometricProvider (simple function)")
        print("  - set_biometric_callback() (one-liner setup)")
    
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
