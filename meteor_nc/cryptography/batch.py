"""
Meteor-NC batch KEM / hybrid encryption (v3).

GPU (CuPy) or CPU (NumPy) batching on top of ``frodo_batch.BatchFrodoKEM``.
Keys, KEM wires and hybrid ciphertexts use exactly the same formats as
``core.LWEKEM`` / ``core.HybridKEM``, so batch output can be decapsulated
one at a time and vice versa. This replaces the v2 batch backend, which
implemented the broken v2 construction (see SECURITY.md).

    kem = BatchLWEKEM(n=256)                 # backend="auto": CuPy if a GPU is present
    pk, sk = kem.key_gen()
    K, wires = kem.encaps_batch(100_000)     # K: (B, 32) uint8, wires: (B, wire_len) uint8
    K2 = kem.decaps_batch(wires)             # == K
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple, Union

import numpy as np

from .core import (
    KDF_DOMAIN,
    LWEKEM,
    _HDR,
    _WIRE_VERSION,
    hybrid_open,
    hybrid_parse,
    hybrid_seal,
)
from .frodo_batch import BatchFrodoKEM, CUPY_AVAILABLE


class BatchLWEKEM:
    """Batched v3 LWEKEM (FrodoKEM core), wire-compatible with ``LWEKEM``."""

    def __init__(self, n: int = 256, device_id: int = 0, backend: str = "auto",
                 matmul: str = "auto", **_ignored):
        self._kem = LWEKEM(n=n)                     # keys, wire format, single ops
        self.n = self._kem.n
        self.params = self._kem.params
        self.device_id = int(device_id)
        with self._device(backend):
            self._batch = BatchFrodoKEM(self.params, backend=backend, matmul=matmul)
        self.backend = self._batch.backend

    def _device(self, backend: Optional[str] = None):
        """Device context for every batch call (device selection is per thread)."""
        import contextlib
        backend = backend or getattr(self, "backend", "auto")
        if CUPY_AVAILABLE and backend != "numpy":
            import cupy as cp
            return cp.cuda.Device(self.device_id)
        return contextlib.nullcontext()

    # -- keys (delegated) ------------------------------------------------
    def key_gen(self, seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        self._kem.seed = seed
        return self._kem.key_gen()

    def load_public_key(self, pk_bytes: bytes) -> None:
        self._kem.load_public_key(pk_bytes)
        self.params = self._kem.params
        if self._batch.p is not self.params:
            with self._device():
                self._batch = BatchFrodoKEM(self.params, backend=self.backend,
                                            matmul=self._batch.matmul)

    def load_secret_key(self, sk_bytes: bytes) -> None:
        self._kem.load_secret_key(sk_bytes)

    def load_keys(self, pk_bytes: bytes, sk_bytes: bytes) -> None:
        self.load_public_key(pk_bytes)
        self.load_secret_key(sk_bytes)

    @property
    def pk(self):
        return self._kem.pk

    def get_public_key_size(self) -> int:
        return self._kem.get_public_key_size()

    def get_ciphertext_size(self) -> int:
        return self._kem.get_ciphertext_size()

    # -- single (same as LWEKEM) ------------------------------------------
    def encaps(self) -> Tuple[bytes, bytes]:
        return self._kem.encaps()

    def decaps(self, wire: bytes) -> bytes:
        return self._kem.decaps(wire)

    # -- batch ------------------------------------------------------------
    def _header(self) -> bytes:
        return _HDR.pack(_WIRE_VERSION, self.params.nist_level, self.params.n)

    def _kdf_rows(self, ss):
        """K = SHAKE256(KDF_DOMAIN || ss) per row, on the batch backend."""
        bk = self._batch
        dom = bk._const_rows(KDF_DOMAIN, ss.shape[0])
        return bk._hash_rows(bk.xp.concatenate([dom, ss], axis=1), 32, "shake256")

    def encaps_batch(self, batch: int, mu_salt=None, raw: bool = False,
                     device: bool = False):
        """Encapsulate ``batch`` times to the loaded public key.

        Returns (K, wires): K is (batch, 32) uint8 (as LWEKEM's K), wires is
        (batch, wire_len) uint8. ``raw=True`` returns the FrodoKEM shared
        secrets instead of K. ``device=True`` leaves both on the GPU (CuPy
        arrays) instead of copying them to the host. ``mu_salt`` fixes the
        randomness (tests only).
        """
        if self._kem.pk is None:
            raise ValueError("Public key not initialized")
        pk, bk = self._kem.pk.frodo_pk, self._batch
        with self._device():
            if mu_salt is None:
                wires, ss = bk.encaps_batch_random(pk, int(batch), to_host=False,
                                                   prefix=self._header())
            else:
                wires, ss = bk.encaps_batch(pk, mu_salt, to_host=False, prefix=self._header())
            K = ss if raw else self._kdf_rows(ss)
            if device:
                return K, wires
            return bk.to_host(K), bk.to_host(wires)

    def decaps_batch(self, wires, raw: bool = False, device: bool = False):
        """Decapsulate rows of ``wires``: (B, wire_len) uint8 host or device
        array, or a list of bytes. Returns K (B, 32) uint8 (host unless
        ``device=True``)."""
        if self._kem.sk is None:
            raise ValueError("Secret key not initialized")
        bk = self._batch
        if isinstance(wires, (list, tuple)):
            wires = np.stack([np.frombuffer(w, np.uint8) for w in wires])
        if wires.ndim != 2 or wires.shape[1] != _HDR.size + self.params.ct_bytes:
            raise ValueError("wires must have shape (batch, wire_len)")
        with self._device():
            w = bk.xp.asarray(wires)
            hdr = bk.xp.asarray(np.frombuffer(self._header(), np.uint8))
            if not bool((w[:, :_HDR.size] == hdr[None, :]).all()):
                raise ValueError("wire header mismatch (version or level)")
            ss = bk.decaps_batch(self._kem.sk, w, to_host=False, offset=_HDR.size)
            K = ss if raw else self._kdf_rows(ss)
            return K if device else bk.to_host(K)


@dataclass
class BatchCiphertext:
    """Parsed hybrid ciphertext (same byte format as HybridKEM)."""
    kem_wire: bytes
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def to_bytes(self) -> bytes:
        import struct
        return (struct.pack(">I", len(self.kem_wire)) + self.kem_wire + self.nonce +
                struct.pack(">I", len(self.ciphertext)) + self.ciphertext + self.tag)

    @classmethod
    def from_bytes(cls, data: bytes) -> "BatchCiphertext":
        return cls(*hybrid_parse(data))


class BatchHybridKEM:
    """Batched KEM + the HybridKEM DEM; ciphertexts interoperate with HybridKEM."""

    def __init__(self, n: int = 256, device_id: int = 0, backend: str = "auto",
                 mixer_rounds: int = 8, **_ignored):
        self.kem = BatchLWEKEM(n=n, device_id=device_id, backend=backend)
        self.mixer_rounds = int(mixer_rounds)

    def key_gen(self, seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        return self.kem.key_gen(seed=seed)

    def load_public_key(self, pk_bytes: bytes) -> None:
        self.kem.load_public_key(pk_bytes)

    def load_secret_key(self, sk_bytes: bytes) -> None:
        self.kem.load_secret_key(sk_bytes)

    def load_keys(self, pk_bytes: bytes, sk_bytes: bytes) -> None:
        self.kem.load_keys(pk_bytes, sk_bytes)

    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        return self.encrypt_batch([plaintext], aad)[0]

    def decrypt(self, ct: Union[bytes, BatchCiphertext], aad: Optional[bytes] = None) -> bytes:
        return self.decrypt_batch([ct], aad)[0]

    def encrypt_batch(self, plaintexts: List[bytes], aad: Optional[bytes] = None) -> List[bytes]:
        K, wires = self.kem.encaps_batch(len(plaintexts))
        return [hybrid_seal(K[i].tobytes(), wires[i].tobytes(), pt, aad, self.mixer_rounds)
                for i, pt in enumerate(plaintexts)]

    def decrypt_batch(self, ciphertexts: List[Union[bytes, BatchCiphertext]],
                      aad: Optional[bytes] = None) -> List[bytes]:
        parts = [hybrid_parse(c.to_bytes() if isinstance(c, BatchCiphertext) else c)
                 for c in ciphertexts]
        K = self.kem.decaps_batch([p[0] for p in parts])
        return [hybrid_open(K[i].tobytes(), p[1], p[2], p[3], aad, self.mixer_rounds)
                for i, p in enumerate(parts)]


__all__ = ["BatchLWEKEM", "BatchHybridKEM", "BatchCiphertext"]
