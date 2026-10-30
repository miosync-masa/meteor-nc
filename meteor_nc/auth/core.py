# meteor_nc/auth/core.py
"""
Meteor-Auth: Device-Bound Quantum-Resistant Authentication

Passwordless authentication: user seed (knowledge) + device secret
(possession) -> device-bound v3 identity, with challenge-response login.

Features:
    - Device-bound keys (knowledge + possession; biometric gate optional,
      a real factor only with a hardware keystore - see DeviceKeyStore)
    - Passwordless authentication via QR code
    - Post-quantum (v3 KEM + hybrid Ed25519/ML-DSA-65 signatures)
    - Zero server trust (no password storage)
    - Full P2P integration
    - Biometric hook for iOS/Android integration

v3: see SECURITY.md for what changed and why.
"""

from __future__ import annotations

import hmac
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..cryptography.common import _sha256
from ..protocols.envelope import MeteorIdentity
from ..protocols.meteor_protocol import MeteorMessage, MeteorNode

logger = logging.getLogger("meteor-auth")


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
    
    Used when biometrics are not required. Never reports success on its own
    (fail closed): requiring biometrics without a real provider is an error.
    """
    
    def verify(self) -> BiometricStatus:
        return BiometricStatus.NOT_AVAILABLE
    
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
# Device secret storage (the possession factor)
# =============================================================================

class DeviceKeyStore:
    """
    Holds this device's 32-byte secret, the possession factor.

    v2 used a "fingerprint" of public machine properties (MAC address, OS
    strings), which an attacker holding the user seed could brute-force
    offline (about a minute for 2^24 MAC candidates), and which changed on
    OS updates or when no MAC was found. v3 uses a random secret that exists
    only where it was created.

    Implementations decide where the secret lives. For the secret (and any
    biometric gate in front of it) to resist someone with full access to the
    device's files, back it with a hardware keystore that releases it only
    after user verification: iOS Secure Enclave / Keychain with
    ``.biometryCurrentSet``, Android Keystore with
    ``setUserAuthenticationRequired(true)``, or a TPM.
    """

    def load_or_create(self) -> bytes:
        raise NotImplementedError

    def exists(self) -> bool:
        raise NotImplementedError


class FileDeviceKeyStore(DeviceKeyStore):
    """Secret in a file only the owner can read (0600), created on first use.

    Default path: ``$METEOR_NC_DEVICE_KEY`` or ``~/.meteor_nc/device_key``.
    Losing the file means a new device identity (re-register; keep the user
    seed). Copying the file copies the device.
    """

    def __init__(self, path: Optional[str] = None):
        self.path = Path(path or os.environ.get("METEOR_NC_DEVICE_KEY")
                         or Path.home() / ".meteor_nc" / "device_key")

    def exists(self) -> bool:
        return self.path.exists()

    def _read(self) -> bytes:
        if os.name == "posix" and self.path.stat().st_mode & 0o077:
            raise MeteorAuthError(f"device key {self.path} is readable by other users "
                                  "(chmod 600 it, or delete it to start a new device identity)")
        data = self.path.read_bytes()
        if len(data) != 32:
            raise MeteorAuthError(f"device key {self.path} is corrupted")
        return data

    def load_or_create(self) -> bytes:
        if self.path.exists():
            return self._read()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:                     # created concurrently
            return self._read()
        try:
            os.write(fd, secrets.token_bytes(32))
            os.fsync(fd)
        finally:
            os.close(fd)
        return self._read()


class MemoryDeviceKeyStore(DeviceKeyStore):
    """Secret kept in memory only (tests, ephemeral sessions)."""

    def __init__(self, secret: Optional[bytes] = None):
        if secret is not None and len(secret) != 32:
            raise ValueError("device secret must be 32 bytes")
        self._secret = secret

    def exists(self) -> bool:
        return self._secret is not None

    def load_or_create(self) -> bytes:
        if self._secret is None:
            self._secret = secrets.token_bytes(32)
        return self._secret


# =============================================================================
# Client Authentication
# =============================================================================

class MeteorAuth:
    """
    Meteor-Auth client: user seed + device secret -> device-bound identity.

    Factors:
    - Knowledge: the 32-byte user seed (e.g. kept as a QR code).
    - Possession: a random 32-byte device secret in a DeviceKeyStore.
      ``device-bound seed = SHA256(domain || user_seed || device_secret)``;
      neither alone determines the identity.
    - Biometrics (``require_biometric``): checked before the device secret is
      read. In pure Python this is an application-level gate, not a
      cryptographic factor: code running as the user can read the secret
      directly. It becomes a real factor only when the DeviceKeyStore is a
      hardware keystore that itself demands user verification (see
      DeviceKeyStore).

    Example:
        >>> auth = MeteorAuth()
        >>> user_seed = auth.generate_seed()          # keep it safe
        >>> node = auth.login(user_seed)              # MeteorNode bound to this device
        >>> node.get_meteor_id() == auth.get_meteor_id(user_seed)
        True
    """

    def __init__(
        self,
        gpu: bool = False,
        device_id: int = 0,
        require_biometric: bool = False,
        biometric_provider: Optional[BiometricProvider] = None,
        device_store: Optional[DeviceKeyStore] = None,
    ):
        self.gpu = False
        self.device_id = device_id
        self.require_biometric = require_biometric
        self._biometric_provider = biometric_provider
        self.device_store = device_store or FileDeviceKeyStore()
        self._last_biometric_time: Optional[float] = None
        self._biometric_valid_duration: float = 300.0  # 5 minutes

    # -- biometrics ----------------------------------------------------------
    @property
    def biometric_provider(self) -> BiometricProvider:
        return self._biometric_provider or DefaultBiometricProvider()

    def set_biometric_provider(self, provider: BiometricProvider) -> None:
        self._biometric_provider = provider

    def set_biometric_callback(self, verify_callback: Callable[[], bool],
                               is_available_callback: Optional[Callable[[], bool]] = None,
                               biometric_type: str = "callback") -> None:
        self._biometric_provider = CallbackBiometricProvider(
            verify_callback=verify_callback,
            is_available_callback=is_available_callback,
            biometric_type=biometric_type,
        )

    def _verify_biometric(self) -> BiometricStatus:
        if self._last_biometric_time is not None:
            if time.time() - self._last_biometric_time < self._biometric_valid_duration:
                return BiometricStatus.SUCCESS
        status = self.biometric_provider.verify()
        if status == BiometricStatus.SUCCESS:
            self._last_biometric_time = time.time()
        return status

    def is_biometric_available(self) -> bool:
        return self.biometric_provider.is_available()

    def get_biometric_type(self) -> str:
        return self.biometric_provider.get_type()

    def invalidate_biometric(self) -> None:
        self._last_biometric_time = None

    def _require_user_presence(self) -> None:
        if not self.require_biometric:
            return
        provider = self.biometric_provider
        if not provider.is_available():
            raise BiometricRequiredError(
                f"Biometric authentication required but not available. "
                f"Provider: {provider.get_type()}")
        status = self._verify_biometric()
        if status != BiometricStatus.SUCCESS:
            raise BiometricFailedError(status)

    # -- device binding ------------------------------------------------------
    def _device_secret(self) -> bytes:
        self._require_user_presence()
        return self.device_store.load_or_create()

    def get_device_fingerprint(self) -> bytes:
        """Public, stable identifier of this device (one-way from its secret).
        Safe to display; not usable to derive keys."""
        return _sha256(b"METEOR_AUTH_DEVICE_ID_v3", self._device_secret())

    def generate_seed(self) -> bytes:
        """New 32-byte user seed (knowledge factor). Store it safely."""
        return secrets.token_bytes(32)

    def create_device_bound_seed(self, user_seed: bytes) -> bytes:
        """SHA256(domain || user_seed || device_secret)."""
        if len(user_seed) != 32:
            raise ValueError("User seed must be 32 bytes")
        return _sha256(b"METEOR_AUTH_DEVICE_BOUND_v3", user_seed + self._device_secret())

    def get_meteor_id(self, user_seed: bytes) -> bytes:
        """MeteorID that ``login(user_seed)`` produces on this device (public)."""
        return MeteorIdentity(self.create_device_bound_seed(user_seed)).meteor_id

    def login(self, user_seed: bytes, node_name: Optional[str] = None) -> MeteorNode:
        """Create the device-bound MeteorNode (checks biometrics first when required).

        Raises:
            BiometricRequiredError: biometric required but not available
            BiometricFailedError: biometric verification failed
        """
        return MeteorNode(name=node_name or "AuthClient",
                          seed=self.create_device_bound_seed(user_seed))

    def export_qr_data(self, user_seed: bytes) -> str:
        """Hex of the user seed for a QR code. Whoever sees it has the
        knowledge factor; the device secret is still needed to log in."""
        return user_seed.hex()

    def import_qr_data(self, qr_data: str) -> bytes:
        seed = bytes.fromhex(qr_data)
        if len(seed) != 32:
            raise ValueError("Invalid QR data: seed must be 32 bytes")
        return seed


def answer_challenge(node: MeteorNode, server_name: str, challenge: bytes) -> MeteorMessage:
    """Client side of MeteorAuthServer.authenticate: send the challenge back,
    encrypted to and signed for the server (envelope binds sender and recipient)."""
    return node.send(server_name, challenge)


# =============================================================================
# Server Authentication
# =============================================================================

@dataclass
class UserRecord:
    """User record stored by server."""
    meteor_id: bytes
    public_key: Any                       # public bundle
    token: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    registered_at: float = field(default_factory=time.time)
    last_auth: Optional[float] = None


class MeteorAuthServer:
    """
    Challenge-response server. Stores only MeteorIDs and public bundles.

    ``authenticate`` accepts a response only if
    - the challenge for that token exists, has not expired and is used once
      (it is consumed by any attempt),
    - the response comes from the MeteorID registered for that token (an
      envelope signed by that user and addressed to this server),
    - its content equals the challenge (constant-time comparison).
    """

    def __init__(self, node_name: str = "AuthServer", gpu: bool = False, device_id: int = 0,
                 challenge_ttl_s: float = 60.0, seed: Optional[bytes] = None):
        self.node = MeteorNode(name=node_name, seed=seed)
        self.gpu = False
        self.device_id = device_id
        self.challenge_ttl_s = float(challenge_ttl_s)
        self.users: Dict[str, UserRecord] = {}
        self.challenges: Dict[str, Tuple[bytes, float]] = {}
        self._lock = threading.Lock()

    def get_server_id(self) -> bytes:
        return self.node.get_meteor_id()

    def get_server_public_key(self) -> bytes:
        return self.node.get_public_key()

    def register(self, meteor_id: bytes, public_key: bytes,
                 metadata: Optional[Dict[str, Any]] = None) -> str:
        """Register a user (MeteorID + public bundle). Returns the user token.
        Raises ValueError if the bundle does not match the MeteorID."""
        if len(meteor_id) != 32:
            raise ValueError("MeteorID must be 32 bytes")
        token = secrets.token_hex(32)
        self.node.add_peer(token, meteor_id, public_key)       # verifies the bundle
        with self._lock:
            self.users[token] = UserRecord(meteor_id=meteor_id, public_key=public_key,
                                           token=token, metadata=metadata or {})
        logger.info("[%s] registered user %s...", self.node.name, token[:16])
        return token

    def create_challenge(self, token: str) -> bytes:
        """New single-use 32-byte challenge for ``token`` (replaces any pending one)."""
        with self._lock:
            if token not in self.users:
                raise ValueError("Unknown token")
            challenge = secrets.token_bytes(32)
            self.challenges[token] = (challenge, time.time() + self.challenge_ttl_s)
        return challenge

    def authenticate(self, token: str, encrypted_response: MeteorMessage) -> bool:
        with self._lock:
            record = self.users.get(token)
            pending = self.challenges.pop(token, None)          # single use
        if record is None or pending is None:
            logger.info("[auth] rejected: unknown token or no pending challenge")
            return False
        challenge, expires = pending
        if time.time() > expires:
            logger.info("[auth] rejected: challenge expired")
            return False
        if encrypted_response.sender_id != record.meteor_id:
            logger.info("[auth] rejected: response not from the token's owner")
            return False
        try:
            answer = self.node.receive(encrypted_response)
        except ValueError as e:
            logger.info("[auth] rejected: %s", e)
            return False
        if not hmac.compare_digest(answer, challenge):
            logger.info("[auth] rejected: challenge mismatch")
            return False
        with self._lock:
            if token in self.users:
                self.users[token].last_auth = time.time()
        return True

    def get_user(self, token: str) -> Optional[UserRecord]:
        return self.users.get(token)

    def get_user_by_meteor_id(self, meteor_id: bytes) -> Optional[UserRecord]:
        for record in self.users.values():
            if record.meteor_id == meteor_id:
                return record
        return None

    def revoke(self, token: str) -> bool:
        """Revoke a token: its record, pending challenge and peer entry go away."""
        with self._lock:
            if self.users.pop(token, None) is None:
                return False
            self.challenges.pop(token, None)
        self.node.remove_peer(token)
        return True

    def list_users(self) -> List[Dict[str, Any]]:
        return [{
            'token': record.token[:16] + '...',
            'meteor_id': record.meteor_id.hex()[:16] + '...',
            'metadata': record.metadata,
            'registered_at': record.registered_at,
            'last_auth': record.last_auth,
        } for record in self.users.values()]


# =============================================================================
# Utility Functions
# =============================================================================

def verify_device_binding(user_seed: bytes, expected_meteor_id: bytes,
                          device_store: Optional[DeviceKeyStore] = None) -> bool:
    """True if ``user_seed`` on this device (its device secret) gives ``expected_meteor_id``."""
    return hmac.compare_digest(
        MeteorAuth(device_store=device_store).get_meteor_id(user_seed), expected_meteor_id)


def generate_recovery_codes(user_seed: bytes, count: int = 8) -> List[str]:
    """
    Readable codes derived from the user seed (e.g. to check a printed backup).

    Note: they are a function of the seed, so they carry no more and no less
    than the seed itself, and nothing in Meteor-NC verifies them. They are not
    a second factor and cannot replace a lost device secret.
    """
    codes = []
    for i in range(count):
        code_hex = _sha256(b"METEOR_RECOVERY_v2", user_seed + i.to_bytes(4, 'big'))[:8].hex().upper()
        codes.append(f"{code_hex[:4]}-{code_hex[4:8]}-{code_hex[8:12]}-{code_hex[12:16]}")
    return codes


# =============================================================================
# Test Suite
# =============================================================================

def run_tests() -> bool:
    """Quick self-check (the full suite is tests/test_auth.py)."""
    store = MemoryDeviceKeyStore()
    auth = MeteorAuth(device_store=store)
    seed = auth.generate_seed()
    node = auth.login(seed, "Client")
    ok = node.get_meteor_id() == auth.get_meteor_id(seed)
    ok &= MeteorAuth(device_store=MemoryDeviceKeyStore()).get_meteor_id(seed) != node.get_meteor_id()
    server = MeteorAuthServer("Server")
    node.add_peer("Server", server.get_server_id(), server.get_server_public_key())
    token = server.register(node.get_meteor_id(), node.get_public_key())
    ch = server.create_challenge(token)
    ok &= server.authenticate(token, answer_challenge(node, "Server", ch))
    print("Meteor-Auth self-check:", "PASS" if ok else "FAIL")
    return bool(ok)


if __name__ == "__main__":
    run_tests()
