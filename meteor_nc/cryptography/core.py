# meteor_nc/cryptography/core.py
"""
Meteor-NC Core Components (v3)

LWEKEM: IND-CCA2 KEM whose core is FrodoKEM-640/976/1344-SHAKE
(meteor_nc/cryptography/frodo.py, byte-exact with the official KATs),
plus HybridKEM (KEM-DEM with a Feistel mixer and AES-GCM).

v3 replaces the v2 construction, which was broken: v2 hid all message bits
under one shared scalar mask, allowing passive key recovery from (pk, ct).
See SECURITY.md.

Wire formats (all with a 12-byte big-endian header: version=3, level, frodo_n):
  - Public key : header + FrodoKEM pk  (seedA || packed B)
  - Secret key : header + FrodoKEM sk  (s || pk || S^T || pkh)
  - Ciphertext : header + FrodoKEM ct  (c1 || c2 || salt)

Levels (legacy selector n -> FrodoKEM):
  - n=256  -> FrodoKEM-640  (NIST L1): PK 9628 B, CT 9764 B
  - n=512  -> FrodoKEM-976  (NIST L3): PK 15644 B, CT 15804 B
  - n=1024 -> FrodoKEM-1344 (NIST L5): PK 21532 B, CT 21708 B

Shared secret: K = HKDF(FrodoKEM ss), 32 bytes.
"""


from __future__ import annotations

import secrets
import struct
from typing import Any, Callable, Optional, Tuple

import numpy as np

# =============================================================================
# Import from common.py
# =============================================================================

from .frodo import FrodoKEM, FrodoParams, PARAMS_BY_LEVEL

from .common import (
    # Constants
    Q_DEFAULT,
    SECURITY_PARAMS,
    GPU_AVAILABLE,
    CRYPTO_AVAILABLE,
    cp,
    AESGCM,
    # Utilities
    _sha256,
    _ct_eq,
    _words_from_bytes_le,
    _bytes_from_words_le,
    prg_sha256,
    small_error_from_seed,
    _derive_key,
    # HKDF
    HKDF,
    # Data structures
    LWEPublicKey,
    LWESecretKey,
    LWECiphertext,
    FullCiphertext,
    # CBD
    CenteredBinomial,
)


# =============================================================================
# Domain-separated HKDF for Meteor-NC
# =============================================================================

_METEOR_SALT = _sha256(b"meteor-nc-v1-hkdf-salt")
_HKDF_INSTANCE = HKDF(salt=_METEOR_SALT)


def _derive_key_meteor(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-based key derivation with Meteor-NC domain separation."""
    return _HKDF_INSTANCE.derive(ikm, info, length)


# =============================================================================
# Symmetric Mixer (Feistel Network)
# =============================================================================

class SymmetricMixer:
    """Feistel network-based reversible mixer."""
    
    def __init__(
        self,
        key: bytes,
        rounds: int = 8,
        gpu: bool = True,
        device_id: int = 0,
    ):
        if len(key) < 32:
            raise ValueError("Key must be at least 32 bytes")
        
        self.rounds = int(rounds)
        self.gpu = bool(gpu and GPU_AVAILABLE)
        self.device_id = int(device_id)
        
        if self.gpu:
            cp.cuda.Device(self.device_id).use()
            self.xp = cp
        else:
            self.xp = np
        
        self._round_keys = self._expand_round_keys(key, self.rounds)
    
    @staticmethod
    def _expand_round_keys(key: bytes, rounds: int) -> list:
        """Derive round constants deterministically from key."""
        out = []
        seed = _sha256(b"symmetric-mixer", key)
        
        for i in range(rounds):
            block = _sha256(seed, struct.pack(">I", i))
            mul = int.from_bytes(block[:4], "little") | 1
            a = (block[4] % 23) + 5
            b = (block[5] % 23) + 5
            out.append((mul, a, b))
        
        return out
    
    def _round_function(self, L: Any, round_idx: int) -> Any:
        """Feistel round function."""
        xp = self.xp
        mul, a, b = self._round_keys[round_idx]
        
        x = L.astype(xp.uint32, copy=False)
        x = (x.astype(xp.uint64) * xp.uint64(mul)) & xp.uint64(0xFFFFFFFF)
        x = x.astype(xp.uint32)
        x = x ^ ((x << xp.uint32(a)) & xp.uint32(0xFFFFFFFF))
        x = x ^ (x >> xp.uint32(b))
        
        return x
    
    def forward(self, plaintext: bytes) -> bytes:
        """Apply forward mixing transformation."""
        xp = self.xp
        orig_len = len(plaintext)
        
        words = _words_from_bytes_le(plaintext)
        nwords = words.shape[0]
        
        if nwords % 2 == 1:
            words = np.concatenate([words, np.zeros(1, dtype=np.uint32)])
            nwords += 1
        
        if self.gpu:
            state = cp.asarray(words, dtype=cp.uint32)
        else:
            state = words.astype(np.uint32)
        
        half = nwords // 2
        L = state[:half].copy()
        R = state[half:].copy()
        
        for r in range(self.rounds):
            F = self._round_function(L, r)
            R = R ^ F
            L, R = R, L
        
        state_out = xp.concatenate([L, R], axis=0)
        
        if self.gpu:
            state_out = cp.asnumpy(state_out)
        
        mixed_bytes = _bytes_from_words_le(np.asarray(state_out, dtype=np.uint32))
        
        return struct.pack(">Q", orig_len) + mixed_bytes
    
    def inverse(self, mixed_with_len: bytes) -> bytes:
        """Apply inverse mixing transformation."""
        xp = self.xp
        
        orig_len = struct.unpack(">Q", mixed_with_len[:8])[0]
        mixed = mixed_with_len[8:]
        
        words = _words_from_bytes_le(mixed)
        nwords = words.shape[0]
        
        if self.gpu:
            state = cp.asarray(words, dtype=cp.uint32)
        else:
            state = words.astype(np.uint32)
        
        half = nwords // 2
        L = state[:half].copy()
        R = state[half:].copy()
        
        for r in reversed(range(self.rounds)):
            L, R = R, L
            F = self._round_function(L, r)
            R = R ^ F
        
        state_out = xp.concatenate([L, R], axis=0)
        
        if self.gpu:
            state_out = cp.asnumpy(state_out)
        
        plaintext_padded = _bytes_from_words_le(np.asarray(state_out, dtype=np.uint32))
        
        return plaintext_padded[:orig_len]


# =============================================================================
# LWE-KEM (v3: FrodoKEM core)
# =============================================================================

# Legacy selector values (v2 "n") and FrodoKEM dimensions both map to a level.
_LEVEL_FOR_N = {256: 1, 640: 1, 512: 3, 976: 3, 1024: 5, 1344: 5}

_WIRE_VERSION = 3
_HDR = struct.Struct(">III")          # version, nist_level, frodo_n


def _params_for_n(n: int) -> FrodoParams:
    try:
        return PARAMS_BY_LEVEL[_LEVEL_FOR_N[int(n)]]
    except KeyError:
        raise ValueError(
            f"Unsupported n={n}; use 256/512/1024 (legacy selectors) "
            f"or 640/976/1344 (FrodoKEM dimensions)") from None


class _PublicKeyView:
    """Read-only view kept for callers that used kem.pk.* in v2."""

    def __init__(self, params: FrodoParams, frodo_pk: bytes):
        self.params = params
        self.frodo_pk = frodo_pk
        self.n = params.n
        self.nbar = params.nbar
        self.q = params.q
        self.seedA = frodo_pk[:params.len_seedA]
        # 32-byte field for the v2-era 64B blob (pk_seed || b_hash);
        # zero padding keeps the blob an injective commitment to pk.
        self.pk_seed = self.seedA.ljust(32, b"\x00")
        self.b_bytes = frodo_pk[params.len_seedA:]
        self.pk_hash = _sha256(b"pk_hash", frodo_pk)


class LWEKEM:
    """
    IND-CCA2 KEM from plain (unstructured) LWE: FrodoKEM-SHAKE.

    v3 replaces the v2 construction, which was insecure (one scalar mask
    shared by all message bits -> passive key recovery; see SECURITY.md).

    API is kept compatible with v2:
      * ``n`` selects the level: 256 -> FrodoKEM-640 (NIST L1),
        512 -> FrodoKEM-976 (L3), 1024 -> FrodoKEM-1344 (L5).
        640/976/1344 are accepted too.
      * ``k``, ``q``, ``eta`` and ``use_compression`` are accepted and
        ignored: FrodoKEM fixes them and its ciphertext is already packed.
      * ``gpu`` is accepted; this core runs on CPU (NumPy).
      * ``key_gen() -> (pk_bytes, sk_bytes)``,
        ``encaps() -> (K, wire)``, ``decaps(wire) -> K`` with 32-byte K.

    K = HKDF(FrodoKEM shared secret). The FrodoKEM layer itself is
    byte-identical to the reference implementation (tests/test_frodo_kat.py).
    """

    def __init__(
        self,
        n: int = 256,
        k: Optional[int] = None,
        q: Optional[int] = None,
        eta: Optional[int] = None,
        gpu: bool = False,
        device_id: int = 0,
        seed: Optional[bytes] = None,
        use_compression: bool = True,
    ):
        self.params = _params_for_n(n)
        self.level = self.params.nist_level
        self.n = int(n)                    # selector as given by caller
        self.q = self.params.q
        self.gpu = False
        self.device_id = int(device_id)
        self.use_compression = bool(use_compression)
        self.seed = seed
        self.msg_bytes = self.params.len_sec
        self.msg_bits = 8 * self.msg_bytes
        self._frodo = FrodoKEM(self.params)
        self.pk: Optional[_PublicKeyView] = None
        self._sk: Optional[bytes] = None

    # -- serialization -------------------------------------------------------
    def _wrap(self, body: bytes) -> bytes:
        return _HDR.pack(_WIRE_VERSION, self.level, self.params.n) + body

    def _unwrap(self, data: bytes, expected_len: int, what: str) -> bytes:
        if len(data) < _HDR.size:
            raise ValueError(f"{what} too short")
        ver, level, fn = _HDR.unpack(data[:_HDR.size])
        if ver != _WIRE_VERSION:
            raise ValueError(
                f"{what}: unsupported format (version field {ver}); "
                f"Meteor-NC v2 keys are insecure and not accepted")
        if level != self.level or fn != self.params.n:
            raise ValueError(f"{what}: level mismatch ({fn} vs {self.params.n})")
        body = data[_HDR.size:]
        if len(body) != expected_len:
            raise ValueError(f"{what}: wrong length")
        return body

    # -- keys ----------------------------------------------------------------
    def key_gen(self) -> Tuple[bytes, bytes]:
        p = self.params
        nrand = p.len_sec + p.len_seedSE + p.len_z
        if self.seed is not None:
            hk = HKDF(salt=_sha256(b"meteor-nc-v3-keygen"))
            rnd = hk.expand(hk.extract(self.seed), b"frodo-keygen", nrand)
        else:
            rnd = secrets.token_bytes(nrand)
        pk, sk = self._frodo.keygen_from_seed(rnd)
        self.pk = _PublicKeyView(p, pk)
        self._sk = sk
        return self._wrap(pk), self._wrap(sk)

    def load_public_key(self, pk_bytes: bytes) -> None:
        if len(pk_bytes) >= _HDR.size:
            _, level, fn = _HDR.unpack(pk_bytes[:_HDR.size])
            if fn in _LEVEL_FOR_N and _params_for_n(fn) is not self.params:
                self.__init__(n=fn, device_id=self.device_id,
                              use_compression=self.use_compression)
        body = self._unwrap(pk_bytes, self.params.pk_bytes, "public key")
        self.pk = _PublicKeyView(self.params, body)
        self._sk = None

    def load_secret_key(self, sk_bytes: bytes) -> None:
        body = self._unwrap(sk_bytes, self.params.sk_bytes, "secret key")
        embedded_pk = body[self.params.len_sec:self.params.len_sec + self.params.pk_bytes]
        if self.pk is not None and self.pk.frodo_pk != embedded_pk:
            raise ValueError("secret key does not match loaded public key")
        self.pk = _PublicKeyView(self.params, embedded_pk)
        self._sk = body

    def _import_secret_key(self, data: bytes) -> None:
        self.load_secret_key(data)

    @property
    def sk(self):
        return self._sk

    def get_public_key_bytes(self) -> bytes:
        if self.pk is None:
            raise ValueError("Public key not initialized")
        return self._wrap(self.pk.frodo_pk)

    def get_public_key_size(self) -> int:
        return _HDR.size + self.params.pk_bytes

    def get_ciphertext_size(self) -> int:
        return _HDR.size + self.params.ct_bytes

    # -- KEM -----------------------------------------------------------------
    @staticmethod
    def _kdf(ss: bytes) -> bytes:
        return _derive_key_meteor(ss, b"meteor-nc-v3-shared-secret")

    def encaps(self, rng: Optional[Callable[[int], bytes]] = None) -> Tuple[bytes, bytes]:
        if self.pk is None:
            raise ValueError("Public key not initialized")
        p = self.params
        rnd = (rng or secrets.token_bytes)(p.len_sec + p.len_salt)
        ct, ss = self._frodo.encaps_from_seed(self.pk.frodo_pk, rnd)
        return self._kdf(ss), self._wrap(ct)

    def decaps(self, wire: bytes) -> bytes:
        if self.pk is None or self._sk is None:
            raise ValueError("Keys not initialized (need both pk and sk for decaps)")
        ct = self._unwrap(bytes(wire), self.params.ct_bytes, "ciphertext")
        return self._kdf(self._frodo.decaps(self._sk, ct))

    # v2 names kept as aliases; the wire is the only ciphertext form in v3.
    def encaps_uncompressed(self, rng=None):
        return self.encaps(rng)

    def decaps_uncompressed(self, wire: bytes) -> bytes:
        return self.decaps(wire)

# =============================================================================
# Hybrid Cryptosystem
# =============================================================================


# =============================================================================
# Hybrid DEM (shared by HybridKEM and BatchHybridKEM)
# =============================================================================

def hybrid_seal(K: bytes, kem_wire: bytes, plaintext: bytes,
                aad: Optional[bytes], mixer_rounds: int = 8) -> bytes:
    """Mixer + AES-GCM under keys derived from K; serialize with kem_wire."""
    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography library required")
    aead_key = _derive_key_meteor(K, b"meteor-nc-aead-key")
    mixer_key = _derive_key_meteor(K, b"meteor-nc-mixer-key")
    mixed = SymmetricMixer(key=mixer_key, rounds=mixer_rounds, gpu=False).forward(plaintext)
    nonce = secrets.token_bytes(12)
    ct_with_tag = AESGCM(aead_key).encrypt(nonce, mixed, aad)
    ct_body, tag = ct_with_tag[:-16], ct_with_tag[-16:]
    return (struct.pack(">I", len(kem_wire)) + kem_wire + nonce +
            struct.pack(">I", len(ct_body)) + ct_body + tag)


def hybrid_parse(ciphertext: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
    """Split a hybrid ciphertext into (kem_wire, nonce, ct_body, tag)."""
    if len(ciphertext) < 4:
        raise ValueError("Ciphertext too short")
    kem_wire_len = struct.unpack(">I", ciphertext[:4])[0]
    o = 4
    kem_wire = ciphertext[o:o + kem_wire_len]; o += kem_wire_len
    nonce = ciphertext[o:o + 12]; o += 12
    if len(ciphertext) < o + 4:
        raise ValueError("Ciphertext truncated")
    ct_len = struct.unpack(">I", ciphertext[o:o + 4])[0]; o += 4
    ct_body = ciphertext[o:o + ct_len]; o += ct_len
    tag = ciphertext[o:o + 16]
    if len(kem_wire) != kem_wire_len or len(nonce) != 12 or len(ct_body) != ct_len or len(tag) != 16:
        raise ValueError("Ciphertext truncated")
    return kem_wire, nonce, ct_body, tag


def hybrid_open(K: bytes, nonce: bytes, ct_body: bytes, tag: bytes,
                aad: Optional[bytes], mixer_rounds: int = 8) -> bytes:
    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography library required")
    aead_key = _derive_key_meteor(K, b"meteor-nc-aead-key")
    mixer_key = _derive_key_meteor(K, b"meteor-nc-mixer-key")
    mixed = AESGCM(aead_key).decrypt(nonce, ct_body + tag, aad)
    return SymmetricMixer(key=mixer_key, rounds=mixer_rounds, gpu=False).inverse(mixed)


class HybridKEM:
    """
    Hybrid Key Encapsulation Mechanism.
    
    Combines LWE-KEM with symmetric encryption (mixer + AEAD).
    """
    
    def __init__(
        self,
        security_level: int = 128,
        gpu: bool = True,
        device_id: int = 0,
        mixer_rounds: int = 8,
        use_compression: bool = True,
    ):
        if security_level not in SECURITY_PARAMS:
            raise ValueError(f"Unsupported security level: {security_level}")
        
        params = SECURITY_PARAMS[security_level]
        self.security_level = int(security_level)
        self.n = int(params["n"])
        self.gpu = bool(gpu and GPU_AVAILABLE)
        self.device_id = int(device_id)
        self.mixer_rounds = int(mixer_rounds)
        self.use_compression = bool(use_compression)
        
        self.kem = LWEKEM(
            n=params["n"],
            k=params["k"],
            q=params["q"],
            eta=params["eta"],
            gpu=self.gpu,
            device_id=self.device_id,
            use_compression=self.use_compression,
        )
    
    def key_gen(self) -> Tuple[bytes, bytes]:
        """Generate key pair."""
        return self.kem.key_gen()
    
    def load_public_key(self, pk_bytes: bytes) -> None:
        """Load recipient's public key for encryption."""
        self.kem.load_public_key(pk_bytes)
    
    def load_keys(self, pk_bytes: bytes, sk_bytes: bytes) -> None:
        """Load both public and secret keys for decryption."""
        self.kem.load_public_key(pk_bytes)
        self.kem.load_secret_key(sk_bytes)
    
    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        """
        Encrypt plaintext with optional associated data.
        
        Returns:
            kem_wire_len (4B) || kem_wire || nonce (12B) || ct_len (4B) || ct || tag (16B)
        """
        K, kem_wire = self.kem.encaps()
        return hybrid_seal(K, kem_wire, plaintext, aad, self.mixer_rounds)
    
    def decrypt(self, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
        """Decrypt ciphertext with optional AAD verification."""
        kem_wire, nonce, ct_body, tag = hybrid_parse(ciphertext)
        K = self.kem.decaps(kem_wire)
        return hybrid_open(K, nonce, ct_body, tag, aad, self.mixer_rounds)
    
    def get_public_key_size(self) -> int:
        """Get public key size in bytes."""
        return self.kem.get_public_key_size()


# =============================================================================
# Test Suite
# =============================================================================

def run_tests() -> bool:
    """Execute test suite."""
    print("=" * 70)
    print("Meteor-NC Core v2.0 Test Suite (Wire-Based FO)")
    print("=" * 70)
    
    use_gpu = GPU_AVAILABLE
    print(f"\nGPU Available: {use_gpu}")
    
    results = {}
    
    # Test 1: Symmetric Mixer
    print("\n[Test 1] Symmetric Mixer")
    print("-" * 40)
    
    mixer_key = secrets.token_bytes(32)
    mixer = SymmetricMixer(key=mixer_key, rounds=8, gpu=use_gpu)
    
    test_sizes = [1, 16, 100, 1000]
    mixer_ok = True
    
    for size in test_sizes:
        msg = secrets.token_bytes(size)
        mixed = mixer.forward(msg)
        recovered = mixer.inverse(mixed)
        ok = (msg == recovered)
        mixer_ok = mixer_ok and ok
        print(f"  Size {size:5d}: {'PASS' if ok else 'FAIL'}")
    
    results["mixer"] = mixer_ok
    
    # Test 2: LWE-KEM with Compression (v2.0)
    print("\n[Test 2] LWE-KEM with Wire-Based FO (v2.0)")
    print("-" * 40)
    
    kem_ok = True
    for level, label in [(128, "128-bit"), (192, "192-bit"), (256, "256-bit")]:
        params = SECURITY_PARAMS[level]
        kem = LWEKEM(n=params["n"], k=params["k"], eta=params["eta"], gpu=use_gpu, use_compression=True)
        pk_bytes, sk_bytes = kem.key_gen()
        
        K1, wire = kem.encaps()
        K2 = kem.decaps(wire)
        match = (K1 == K2)
        kem_ok = kem_ok and match
        
        print(f"  {label}: wire={len(wire)}B, KeyMatch={'PASS' if match else 'FAIL'}")
    
    results["kem_compressed"] = kem_ok
    
    # Test 3: Sender/Receiver Separation
    print("\n[Test 3] Sender/Receiver Separation")
    print("-" * 40)
    
    separation_ok = True
    
    for level, label in [(128, "128-bit"), (192, "192-bit"), (256, "256-bit")]:
        params = SECURITY_PARAMS[level]
        
        receiver = LWEKEM(n=params["n"], k=params["k"], eta=params["eta"], gpu=use_gpu)
        pk_bytes, sk_bytes = receiver.key_gen()
        
        sender = LWEKEM(n=params["n"], k=params["k"], eta=params["eta"], gpu=use_gpu)
        sender.load_public_key(pk_bytes)
        
        K_sender, wire = sender.encaps()
        
        try:
            sender.decaps(wire)
            sender_cannot_decrypt = False
        except ValueError:
            sender_cannot_decrypt = True
        
        K_receiver = receiver.decaps(wire)
        keys_match = (K_sender == K_receiver)
        
        level_ok = sender_cannot_decrypt and keys_match
        separation_ok = separation_ok and level_ok
        
        print(f"  {label}: SenderBlocked={'PASS' if sender_cannot_decrypt else 'FAIL'}, "
              f"KeyMatch={'PASS' if keys_match else 'FAIL'}")
    
    results["separation"] = separation_ok
    
    # Test 4: Wire Size Verification
    print("\n[Test 4] Compressed Wire Size")
    print("-" * 40)
    
    expected_sizes = {256: 518, 512: 1094, 1024: 2310}
    size_ok = True
    
    for level, label in [(128, "128-bit"), (192, "192-bit"), (256, "256-bit")]:
        params = SECURITY_PARAMS[level]
        n = params["n"]
        
        kem = LWEKEM(n=n, gpu=use_gpu, use_compression=True)
        kem.key_gen()
        
        _, wire = kem.encaps()
        actual = len(wire)
        expected = expected_sizes[n]
        
        ok = (actual == expected)
        size_ok = size_ok and ok
        
        print(f"  {label}: {actual}B (expected {expected}B) {'✓' if ok else '✗'}")
    
    results["wire_sizes"] = size_ok
    
    # Test 5: Hybrid Encryption
    if CRYPTO_AVAILABLE:
        print("\n[Test 5] Hybrid Encryption")
        print("-" * 40)
        
        receiver = HybridKEM(security_level=128, gpu=use_gpu)
        pk_bytes, sk_bytes = receiver.key_gen()
        
        sender = HybridKEM(security_level=128, gpu=use_gpu)
        sender.load_public_key(pk_bytes)
        
        msg = b"Test message for hybrid encryption - confidential!"
        ct = sender.encrypt(msg, aad=b"metadata")
        
        receiver_dec = HybridKEM(security_level=128, gpu=use_gpu)
        receiver_dec.load_keys(pk_bytes, sk_bytes)
        pt = receiver_dec.decrypt(ct, aad=b"metadata")
        
        enc_ok = (msg == pt)
        results["encryption"] = enc_ok
        print(f"  Encrypt/Decrypt: {'PASS' if enc_ok else 'FAIL'}")
        
        try:
            _ = receiver_dec.decrypt(ct, aad=b"wrong")
            aead_ok = False
        except Exception:
            aead_ok = True
        results["aead"] = aead_ok
        print(f"  AEAD Integrity: {'PASS' if aead_ok else 'FAIL'}")
    
    # Test 6: FO Implicit Rejection
    print("\n[Test 6] FO Implicit Rejection (Tampered Wire)")
    print("-" * 40)
    
    rejection_ok = True
    
    for level, label in [(128, "128-bit")]:
        params = SECURITY_PARAMS[level]
        
        kem = LWEKEM(n=params["n"], gpu=use_gpu)
        kem.key_gen()
        
        K_orig, wire = kem.encaps()
        
        # Tamper with wire
        wire_tampered = bytearray(wire)
        wire_tampered[10] ^= 0xFF
        wire_tampered = bytes(wire_tampered)
        
        K_tampered = kem.decaps(wire_tampered)
        
        # K should be different (implicit rejection)
        rejected = (K_orig != K_tampered)
        rejection_ok = rejection_ok and rejected
        
        print(f"  {label}: Tampered wire rejected: {'PASS' if rejected else 'FAIL'}")
    
    results["implicit_rejection"] = rejection_ok
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED ✅' if all_pass else 'SOME TESTS FAILED ❌'}")
    
    if all_pass:
        print("\n✓ Wire-based FO verified:")
        print("  - Compressed wire is canonical form")
        print("  - FO comparison uses wire == wire'")
        print("  - Implicit rejection works correctly")
        print("  - ~75% bandwidth reduction achieved")
    
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
