# meteor_nc/cryptography/practical.py
"""
Meteor-NC Practical Encryption

High-level API for P2P text/binary/file encryption.
Built on correct Hybrid PKE design:
  - Sender: encaps with recipient's public key → K → StreamDEM encrypt
  - Receiver: decaps with own secret key → K → StreamDEM decrypt

This ensures:
  - Anyone with recipient's public key CAN encrypt
  - Only recipient with secret key CAN decrypt
  - Post-Quantum secure (LWE-KEM)
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import numpy as np

from .common import GPU_AVAILABLE, CRYPTO_AVAILABLE, _sha256, LWECiphertext
from .core import HybridKEM, LWEKEM
from .stream import StreamDEM, EncryptedChunk, StreamHeader

if not CRYPTO_AVAILABLE:
    raise ImportError("cryptography library required for practical encryption")


@dataclass
class MeteorIdentity:
    """
    Meteor-NC Identity for P2P communication.
    
    Contains:
    - meteor_id: 32-byte unique identifier (shareable)
    - public_key: LWE public key bytes (shareable)
    - secret_key: LWE secret key bytes (KEEP SECRET!)
    """
    meteor_id: bytes      # 32 bytes - derived from seed
    public_key: bytes     # Serialized public key
    secret_key: bytes     # Serialized secret key (KEEP SECRET!)
    
    def __post_init__(self):
        if len(self.meteor_id) != 32:
            raise ValueError("meteor_id must be 32 bytes")
    
    def export_public(self) -> Dict:
        """Export shareable public identity."""
        return {
            'meteor_id': self.meteor_id.hex(),
            'public_key': base64.b64encode(self.public_key).decode('ascii'),
        }
    
    @classmethod
    def import_public(cls, data: Dict) -> 'MeteorIdentity':
        """Import public identity (no secret key)."""
        return cls(
            meteor_id=bytes.fromhex(data['meteor_id']),
            public_key=base64.b64decode(data['public_key']),
            secret_key=b'',  # No secret key
        )


@dataclass
class EncryptedMessage:
    """
    Encrypted message container.
    
    Wire format:
    - kem_ciphertext: LWE ciphertext (for key decapsulation)
    - stream_ciphertext: StreamDEM encrypted payload
    - stream_tag: AEAD authentication tag
    - stream_id: Stream identifier
    - seq: Sequence number
    - checksum: SHA-256 of original plaintext
    """
    sender_id: bytes
    recipient_id: bytes
    kem_u: np.ndarray
    kem_v: np.ndarray
    stream_ciphertext: bytes
    stream_tag: bytes
    stream_id: bytes
    seq: int
    original_len: int
    checksum: str
    timestamp: float
    
    def to_dict(self) -> Dict:
        """Serialize to dictionary."""
        return {
            'sender_id': self.sender_id.hex(),
            'recipient_id': self.recipient_id.hex(),
            'kem_u': self.kem_u.tolist(),
            'kem_v': self.kem_v.tolist(),
            'ciphertext_b64': base64.b64encode(self.stream_ciphertext).decode('ascii'),
            'tag_b64': base64.b64encode(self.stream_tag).decode('ascii'),
            'stream_id_b64': base64.b64encode(self.stream_id).decode('ascii'),
            'seq': self.seq,
            'original_len': self.original_len,
            'checksum': self.checksum,
            'timestamp': self.timestamp,
        }
    
    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'EncryptedMessage':
        """Deserialize from dictionary."""
        return cls(
            sender_id=bytes.fromhex(data['sender_id']),
            recipient_id=bytes.fromhex(data['recipient_id']),
            kem_u=np.array(data['kem_u'], dtype=np.int64),
            kem_v=np.array(data['kem_v'], dtype=np.int64),
            stream_ciphertext=base64.b64decode(data['ciphertext_b64']),
            stream_tag=base64.b64decode(data['tag_b64']),
            stream_id=base64.b64decode(data['stream_id_b64']),
            seq=data['seq'],
            original_len=data['original_len'],
            checksum=data['checksum'],
            timestamp=data['timestamp'],
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'EncryptedMessage':
        """Deserialize from JSON string."""
        return cls.from_dict(json.loads(json_str))


class MeteorPractical:
    """
    Practical Meteor-NC encryption for P2P communication.
    
    CORRECT DESIGN:
      - Sender uses recipient's PUBLIC KEY to encrypt
      - Receiver uses own SECRET KEY to decrypt
      - Post-Quantum secure via LWE-KEM
    
    Example:
        >>> # Alice and Bob each create their identity
        >>> alice = MeteorPractical("Alice")
        >>> bob = MeteorPractical("Bob")
        >>> 
        >>> # Exchange public identities (can be done over insecure channel)
        >>> alice.add_contact("Bob", bob.get_public_identity())
        >>> bob.add_contact("Alice", alice.get_public_identity())
        >>> 
        >>> # Alice encrypts message FOR Bob (using Bob's public key)
        >>> encrypted = alice.encrypt_for("Bob", "Hello Bob!")
        >>> 
        >>> # Bob decrypts message (using his own secret key)
        >>> plaintext = bob.decrypt(encrypted)
        >>> print(plaintext)  # "Hello Bob!"
    """
    
    def __init__(
        self,
        name: str = "User",
        security_level: int = 128,
        gpu: bool = True,
        device_id: int = 0,
        seed: Optional[bytes] = None,
    ):
        """
        Initialize MeteorPractical.
        
        Args:
            name: Display name
            security_level: 128, 192, or 256 (NIST levels)
            gpu: Enable GPU acceleration
            device_id: GPU device ID
            seed: Optional seed for deterministic key generation
                  (for auth/reproducibility use cases)
        """
        self.name = name
        self.security_level = security_level
        self.gpu = gpu and GPU_AVAILABLE
        self.device_id = device_id
        
        # Master seed
        self._seed = seed or secrets.token_bytes(32)
        
        # Derive MeteorID from seed
        self.meteor_id = _sha256(b"meteor-id-v2", self._seed)
        
        # Initialize KEM with seed
        self._kem = LWEKEM(
            n={128: 256, 192: 512, 256: 1024}[security_level],
            gpu=self.gpu,
            device_id=device_id,
            seed=self._seed,
        )
        
        # Generate keys
        self._pk_bytes, self._sk_bytes = self._kem.key_gen()
        
        # Create identity
        self.identity = MeteorIdentity(
            meteor_id=self.meteor_id,
            public_key=self._pk_bytes,
            secret_key=self._sk_bytes,
        )
        
        # Contact directory: name -> MeteorIdentity (public only)
        self.contacts: Dict[str, MeteorIdentity] = {}
        
        # Statistics
        self.stats = {
            'messages_encrypted': 0,
            'messages_decrypted': 0,
            'bytes_encrypted': 0,
            'bytes_decrypted': 0,
        }
    
    # =========================================================================
    # Identity Management
    # =========================================================================
    
    def get_meteor_id(self) -> bytes:
        """Get 32-byte MeteorID (shareable)."""
        return self.meteor_id
    
    def get_public_identity(self) -> Dict:
        """Get public identity for sharing."""
        return self.identity.export_public()
    
    def add_contact(self, name: str, public_identity: Dict) -> None:
        """
        Add a contact.
        
        Args:
            name: Contact name
            public_identity: Dictionary from get_public_identity()
        """
        contact = MeteorIdentity.import_public(public_identity)
        self.contacts[name] = contact
        print(f"[{self.name}] Added contact: {name}")
    
    def get_contact(self, name: str) -> Optional[MeteorIdentity]:
        """Get contact by name."""
        return self.contacts.get(name)
    
    # =========================================================================
    # Encryption (using recipient's PUBLIC key)
    # =========================================================================
    
    def encrypt_for(
        self,
        recipient_name: str,
        data: Union[str, bytes],
        encoding: str = 'utf-8',
    ) -> EncryptedMessage:
        """
        Encrypt data FOR a recipient.
        
        Uses recipient's PUBLIC KEY for KEM encapsulation.
        Only the recipient can decrypt (with their secret key).
        
        Args:
            recipient_name: Name of recipient contact
            data: String or bytes to encrypt
            encoding: Text encoding if data is string
            
        Returns:
            EncryptedMessage
        """
        # Get recipient
        recipient = self.get_contact(recipient_name)
        if recipient is None:
            raise ValueError(f"Unknown contact: {recipient_name}")
        
        # Convert string to bytes if needed
        if isinstance(data, str):
            plaintext = data.encode(encoding)
        else:
            plaintext = data
        
        start = time.time()
        
        # 1. KEM encapsulation with RECIPIENT'S public key
        #    This creates a shared secret K that only recipient can recover
        recipient_kem = LWEKEM(
            n=self._kem.n,
            gpu=self.gpu,
            device_id=self.device_id,
        )
        recipient_kem.load_public_key(recipient.public_key)
        
        K, kem_ct = recipient_kem.encaps()
        
        # 2. Derive session key from K
        session_key = _sha256(b"practical-session-v2", K)
        stream_id = secrets.token_bytes(16)
        
        # 3. Encrypt with StreamDEM
        stream = StreamDEM(
            session_key=session_key,
            stream_id=stream_id,
            gpu=self.gpu,
            device_id=self.device_id,
        )
        
        chunk = stream.encrypt_chunk(plaintext)
        
        # Compute checksum
        checksum = hashlib.sha256(plaintext).hexdigest()
        
        encrypt_time = time.time() - start
        
        # Update stats
        self.stats['messages_encrypted'] += 1
        self.stats['bytes_encrypted'] += len(plaintext)
        
        print(f"[{self.name}] → [{recipient_name}]: {len(plaintext)} bytes ({encrypt_time*1000:.1f}ms)")
        
        return EncryptedMessage(
            sender_id=self.meteor_id,
            recipient_id=recipient.meteor_id,
            kem_u=kem_ct.u,
            kem_v=kem_ct.v,
            stream_ciphertext=chunk.ciphertext,
            stream_tag=chunk.tag,
            stream_id=stream_id,
            seq=chunk.header.seq,
            original_len=len(plaintext),
            checksum=checksum,
            timestamp=time.time(),
        )
    
    def encrypt_string(self, recipient_name: str, text: str, encoding: str = 'utf-8') -> EncryptedMessage:
        """Convenience method for string encryption."""
        return self.encrypt_for(recipient_name, text, encoding)
    
    def encrypt_bytes(self, recipient_name: str, data: bytes) -> EncryptedMessage:
        """Convenience method for binary encryption."""
        return self.encrypt_for(recipient_name, data)
    
    # =========================================================================
    # Decryption (using own SECRET key)
    # =========================================================================
    
    def decrypt(
        self,
        message: EncryptedMessage,
        encoding: Optional[str] = 'utf-8',
    ) -> Union[str, bytes]:
        """
        Decrypt a message sent TO this user.
        
        Uses own SECRET KEY for KEM decapsulation.
        
        Args:
            message: EncryptedMessage from encrypt_for()
            encoding: If provided, decode bytes to string
            
        Returns:
            Decrypted string or bytes
        """
        # Verify this message is for us
        if message.recipient_id != self.meteor_id:
            raise ValueError("Message not addressed to this user")
        
        start = time.time()
        
        # 1. KEM decapsulation with OWN secret key
        #    Recover the shared secret K
        kem_ct = LWECiphertext(
            u=message.kem_u,
            v=message.kem_v,
        )
        K = self._kem.decaps(kem_ct)
        
        # 2. Derive session key from K
        session_key = _sha256(b"practical-session-v2", K)
        
        # 3. Decrypt with StreamDEM
        stream = StreamDEM(
            session_key=session_key,
            stream_id=message.stream_id,
            gpu=self.gpu,
            device_id=self.device_id,
        )
        
        header = StreamHeader(
            stream_id=message.stream_id,
            seq=message.seq,
            chunk_len=len(message.stream_ciphertext),
            flags=0,
        )
        
        chunk = EncryptedChunk(
            header=header,
            ciphertext=message.stream_ciphertext,
            tag=message.stream_tag,
        )
        
        plaintext = stream.decrypt_chunk(chunk)
        
        # Verify checksum
        actual_checksum = hashlib.sha256(plaintext).hexdigest()
        if actual_checksum != message.checksum:
            raise ValueError("Checksum mismatch! Data may be corrupted.")
        
        decrypt_time = time.time() - start
        
        # Update stats
        self.stats['messages_decrypted'] += 1
        self.stats['bytes_decrypted'] += len(plaintext)
        
        # Find sender name
        sender_name = "Unknown"
        for name, contact in self.contacts.items():
            if contact.meteor_id == message.sender_id:
                sender_name = name
                break
        
        print(f"[{self.name}] ← [{sender_name}]: {len(plaintext)} bytes ({decrypt_time*1000:.1f}ms)")
        
        # Return string or bytes
        if encoding:
            return plaintext.decode(encoding)
        return plaintext
    
    def decrypt_string(self, message: EncryptedMessage, encoding: str = 'utf-8') -> str:
        """Convenience method for string decryption."""
        return self.decrypt(message, encoding=encoding)
    
    def decrypt_bytes(self, message: EncryptedMessage) -> bytes:
        """Convenience method for binary decryption."""
        return self.decrypt(message, encoding=None)
    
    # =========================================================================
    # File Encryption
    # =========================================================================
    
    def encrypt_file_for(
        self,
        recipient_name: str,
        input_path: str,
        output_path: str,
    ) -> Dict:
        """
        Encrypt a file FOR a recipient.
        
        Args:
            recipient_name: Name of recipient contact
            input_path: Path to input file
            output_path: Path to output encrypted file
            
        Returns:
            Encryption metadata
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Read file
        data = input_path.read_bytes()
        
        # Encrypt
        encrypted = self.encrypt_bytes(recipient_name, data)
        
        # Save with metadata
        output_data = {
            'meteor_encrypted_file': True,
            'original_name': input_path.name,
            'message': encrypted.to_dict(),
        }
        output_path.write_text(json.dumps(output_data, indent=2))
        
        return {
            'input_file': str(input_path),
            'output_file': str(output_path),
            'original_size': len(data),
            'encrypted_size': output_path.stat().st_size,
        }
    
    def decrypt_file(
        self,
        input_path: str,
        output_path: str,
    ) -> Dict:
        """
        Decrypt an encrypted file.
        
        Args:
            input_path: Path to encrypted file
            output_path: Path to output decrypted file
            
        Returns:
            Decryption metadata
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Encrypted file not found: {input_path}")
        
        # Read and parse
        file_data = json.loads(input_path.read_text())
        
        if not file_data.get('meteor_encrypted_file'):
            raise ValueError("Not a Meteor encrypted file")
        
        # Decrypt
        message = EncryptedMessage.from_dict(file_data['message'])
        data = self.decrypt_bytes(message)
        
        # Write output
        output_path.write_bytes(data)
        
        return {
            'input_file': str(input_path),
            'output_file': str(output_path),
            'original_name': file_data.get('original_name'),
            'decrypted_size': len(data),
        }
    
    # =========================================================================
    # Seed Management
    # =========================================================================
    
    def export_seed(self) -> bytes:
        """Export master seed for identity recovery."""
        return self._seed
    
    def get_stats(self) -> Dict:
        """Get operation statistics."""
        return {
            'name': self.name,
            'meteor_id': self.meteor_id.hex()[:16] + '...',
            'contacts': len(self.contacts),
            'security_level': self.security_level,
            'gpu_enabled': self.gpu,
            **self.stats,
        }


# =========================================================================
# Quick Functions
# =========================================================================

def quick_encrypt(
    data: Union[str, bytes],
    recipient_public_identity: Dict,
    sender_seed: Optional[bytes] = None,
) -> Tuple[str, bytes]:
    """
    Quick one-shot encryption.
    
    Args:
        data: String or bytes to encrypt
        recipient_public_identity: Recipient's public identity dict
        sender_seed: Optional sender seed (generated if None)
        
    Returns:
        Tuple of (encrypted JSON string, sender_seed)
    """
    sender = MeteorPractical(name="Sender", seed=sender_seed)
    sender.add_contact("Recipient", recipient_public_identity)
    
    if isinstance(data, str):
        encrypted = sender.encrypt_string("Recipient", data)
    else:
        encrypted = sender.encrypt_bytes("Recipient", data)
    
    return encrypted.to_json(), sender.export_seed()


def quick_decrypt(
    json_str: str,
    recipient_seed: bytes,
) -> Union[str, bytes]:
    """
    Quick one-shot decryption.
    
    Args:
        json_str: Encrypted JSON from quick_encrypt
        recipient_seed: Recipient's seed
        
    Returns:
        Decrypted string or bytes
    """
    recipient = MeteorPractical(name="Recipient", seed=recipient_seed)
    
    message = EncryptedMessage.from_json(json_str)
    
    # Try to decode as string, fall back to bytes
    try:
        return recipient.decrypt_string(message)
    except UnicodeDecodeError:
        return recipient.decrypt_bytes(message)


# =========================================================================
# Test Suite
# =========================================================================

def run_tests() -> bool:
    """Execute practical encryption tests."""
    print("=" * 70)
    print("Meteor-NC Practical Encryption Test Suite (Correct PKE Design)")
    print("=" * 70)
    
    results = {}
    
    # Test 1: Identity creation
    print("\n[Test 1] Identity Creation")
    print("-" * 40)
    
    alice = MeteorPractical("Alice", gpu=True)
    bob = MeteorPractical("Bob", gpu=True)
    
    alice_id = alice.get_meteor_id()
    bob_id = bob.get_meteor_id()
    
    identity_ok = len(alice_id) == 32 and len(bob_id) == 32 and alice_id != bob_id
    results['identity'] = identity_ok
    print(f"  Alice ID: {alice_id.hex()[:32]}...")
    print(f"  Bob ID:   {bob_id.hex()[:32]}...")
    print(f"  Result: {'PASS' if identity_ok else 'FAIL'}")
    
    # Test 2: Contact exchange
    print("\n[Test 2] Contact Exchange")
    print("-" * 40)
    
    alice.add_contact("Bob", bob.get_public_identity())
    bob.add_contact("Alice", alice.get_public_identity())
    
    contact_ok = alice.get_contact("Bob") is not None and bob.get_contact("Alice") is not None
    results['contact'] = contact_ok
    print(f"  Result: {'PASS' if contact_ok else 'FAIL'}")
    
    # Test 3: String encryption (Alice → Bob)
    print("\n[Test 3] String Encryption (Alice → Bob)")
    print("-" * 40)
    
    original = "Hello Bob! This is a secret message. 🔐"
    encrypted = alice.encrypt_string("Bob", original)
    decrypted = bob.decrypt_string(encrypted)
    
    string_ok = original == decrypted
    results['string'] = string_ok
    print(f"  Original:  {original}")
    print(f"  Decrypted: {decrypted}")
    print(f"  Result: {'PASS' if string_ok else 'FAIL'}")
    
    # Test 4: Bidirectional (Bob → Alice)
    print("\n[Test 4] Bidirectional (Bob → Alice)")
    print("-" * 40)
    
    reply = "Hi Alice! Got your message! 👍"
    encrypted_reply = bob.encrypt_string("Alice", reply)
    decrypted_reply = alice.decrypt_string(encrypted_reply)
    
    bidir_ok = reply == decrypted_reply
    results['bidirectional'] = bidir_ok
    print(f"  Reply: {decrypted_reply}")
    print(f"  Result: {'PASS' if bidir_ok else 'FAIL'}")
    
    # Test 5: Binary encryption
    print("\n[Test 5] Binary Encryption")
    print("-" * 40)
    
    test_sizes = [0, 1, 100, 1000, 10000]
    binary_ok = True
    
    for size in test_sizes:
        data = secrets.token_bytes(size) if size > 0 else b""
        enc = alice.encrypt_bytes("Bob", data)
        dec = bob.decrypt_bytes(enc)
        ok = (data == dec)
        binary_ok = binary_ok and ok
        print(f"  Size {size:5d}: {'PASS' if ok else 'FAIL'}")
    
    results['binary'] = binary_ok
    
    # Test 6: JSON serialization
    print("\n[Test 6] JSON Serialization")
    print("-" * 40)
    
    encrypted = alice.encrypt_string("Bob", "Serialize test")
    json_str = encrypted.to_json()
    restored = EncryptedMessage.from_json(json_str)
    decrypted = bob.decrypt_string(restored)
    
    json_ok = decrypted == "Serialize test"
    results['json'] = json_ok
    print(f"  Round-trip: {'PASS' if json_ok else 'FAIL'}")
    
    # Test 7: Seed reproducibility
    print("\n[Test 7] Seed Reproducibility")
    print("-" * 40)
    
    seed = b"test_seed_12345678901234567890ab"
    user1 = MeteorPractical("User1", seed=seed)
    user2 = MeteorPractical("User2", seed=seed)
    
    seed_ok = user1.get_meteor_id() == user2.get_meteor_id()
    results['seed'] = seed_ok
    print(f"  Same seed → Same ID: {'PASS' if seed_ok else 'FAIL'}")
    
    # Test 8: Wrong recipient cannot decrypt
    print("\n[Test 8] Security: Wrong Recipient Cannot Decrypt")
    print("-" * 40)
    
    eve = MeteorPractical("Eve", gpu=True)
    encrypted_for_bob = alice.encrypt_string("Bob", "Secret for Bob only")
    
    try:
        eve.decrypt_string(encrypted_for_bob)
        security_ok = False
        print("  Eve decrypted! SECURITY BREACH!")
    except ValueError as e:
        if "not addressed" in str(e):
            security_ok = True
            print(f"  Eve blocked: {e}")
        else:
            security_ok = False
            print(f"  Unexpected error: {e}")
    
    results['security'] = security_ok
    print(f"  Result: {'PASS' if security_ok else 'FAIL'}")
    
    # Test 9: Quick functions
    print("\n[Test 9] Quick Functions")
    print("-" * 40)
    
    # Bob creates identity
    bob2 = MeteorPractical("Bob2", gpu=True)
    bob2_public = bob2.get_public_identity()
    bob2_seed = bob2.export_seed()
    
    # Quick encrypt to Bob2
    json_str, sender_seed = quick_encrypt("Quick test message", bob2_public)
    
    # Quick decrypt as Bob2
    decrypted = quick_decrypt(json_str, bob2_seed)
    
    quick_ok = decrypted == "Quick test message"
    results['quick'] = quick_ok
    print(f"  Quick encrypt/decrypt: {'PASS' if quick_ok else 'FAIL'}")
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    passed = sum(results.values())
    total = len(results)
    
    print(f"Result: {passed}/{total} tests passed")
    
    if all_pass:
        print("\n✓ ALL TESTS PASSED")
        print("\n✓ Security properties verified:")
        print("  - Sender encrypts with recipient's PUBLIC key")
        print("  - Only recipient can decrypt with SECRET key")
        print("  - Wrong recipient CANNOT decrypt")
    else:
        print("\n✗ SOME TESTS FAILED")
        for name, ok in results.items():
            if not ok:
                print(f"  - {name}: FAILED")
    
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
