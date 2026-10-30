# Security notice: Meteor-NC v2 is broken

**Do not use Meteor-NC v2.x (including the GPU batch backend).** Version 3
replaces the KEM core with FrodoKEM. Keys and ciphertexts from v2 are
rejected by v3.

## 1. Passive key recovery (critical)

In v2, encryption computed

```
u = A^T r + e1            (vector, length n)
v = <b, r> + e2 + Δ·m     (vector, length n)
```

Here `<b, r>` is a **single scalar**, so every message bit was hidden under
the same mask. For any i, j:

```
v_i − v_j = (e2_i − e2_j) + Δ·(m_i − m_j)
```

With |e2| ≤ 2 and Δ ≈ q/2, this reveals `m_i XOR m_j` exactly. The message
is then known up to a global bit flip, and the right one is found by
re-encrypting both candidates with the public key (the FO transform is
deterministic). The shared secret follows.

The attack uses only the public key and one ciphertext and needs no lattice
reduction. It recovered the shared secret in 20/20 trials at every level
(n = 256, 512, 1024), compressed and uncompressed, in under a second each.
The GPU batch path (`batch.py`) computes `V = b·R + E2 + M` the same way and
is equally affected.

## 2. Parameters below their claimed levels

Even with a correct construction, v2 parameters (q = 2³² − 5, secrets and
errors in [−3, 3]) were far too weak: the ratio of error size to q is tiny,
which makes lattice reduction cheap. A rough primal-uSVP (core-SVP)
estimate gives about 2¹⁵ for n = 256 (labelled "NIST L1") and about 2⁸¹ for
n = 1024 (labelled "NIST L5"). These are rough estimates, not
lattice-estimator outputs, but they are far from the claimed levels.

## 3. What v3 does

* The KEM core is FrodoKEM-640/976/1344-SHAKE (plain LWE, nbar = mbar = 8,
  independent masks per encoded entry), using the published parameters and
  error tables. No new parameters or assumptions are introduced.
* The implementation (`meteor_nc/cryptography/frodo.py`) is byte-identical to
  the FrodoKEM reference: it passes all 300 official NIST KAT vectors
  (`tests/test_frodo_kat.py`).
* `tests/test_core_v3.py` runs the v2 difference attack against v3 as a
  regression test; it must fail.
* The v2 GPU batch backend was removed. The v3 batch backend
  (`batch.py`, `frodo_batch.py`) runs the same FrodoKEM core batched on GPU
  (CuPy) or CPU (NumPy), byte-identical to the single implementation and the
  KATs. Its GPU SHAKE kernel shares its C source with a CPU build that is
  tested against hashlib (`tests/test_shake_kernel.py`).

## Remaining limitations

* Pure Python/NumPy/CuPy: no constant-time guarantees. Research and
  reference use only.
* The GPU path has been verified only through its CPU-equivalent code paths
  in this repository's CI; run `benchmarks/bench_v3_gpu.py` on a CUDA machine
  to check it there (it aborts on any mismatch).
* Sizes grow to FrodoKEM's: public key ~9.6 / 15.6 / 21.5 KB and ciphertext
  ~9.8 / 15.8 / 21.7 KB for L1 / L3 / L5. The small v2 sizes were a
  consequence of the broken construction.

# Protocol layer (v2 → v3)

The v2 protocol code (`protocols/web4.py`, `protocols/meteor_protocol.py`)
had its own, independent breaks. All are fixed in v3; each has a regression
test in `tests/test_protocols.py`.

## Critical

* **Published identifier was the secret seed** (`web4.py`). `Web4Identity`
  set `meteor_id = seed`, derived the KEM secret key and the Ed25519 signing
  key from it, and published the MeteorID (DHT announce, `to_dict`, peer
  exchange). `add_peer` even called `Web4Identity.from_meteor_id(peer_id)`,
  rebuilding the peer's private keys. Anyone who knew a node's MeteorID could
  decrypt all its traffic and sign as it.
* **Signature checks failed open.** Without PyNaCl, `verify()` returned
  `True`, and the fallback "signature" was an HMAC keyed with the public
  MeteorID.
* **No sender authentication.** Signatures were never verified on receive,
  covered only a 64-bit hash of the plaintext, and `meteor_protocol.py` had
  no signature at all, so `sender_id` could be set to anyone.

## Serious

* Header fields (sender, recipient, time, type) were not bound to the AEAD,
  so they could be altered undetected.
* No replay protection across messages.
* `web4.py` sent the first 64 bits of SHA-256(plaintext) in clear, which
  confirms guesses of short messages.
* DHT records were trusted as is (an attacker could map a MeteorID to their
  own key).
* `Web4P2P.send` reported success when nothing was sent.
* `StreamDEM.decrypt_chunk` marked a sequence number as seen before the
  chunk authenticated, so a forged chunk could block the genuine one. Its GPU
  path (XChaCha20) and CPU path (ChaCha20) produced different ciphertexts.

## v3 design (`protocols/envelope.py`)

* A secret seed (never published) derives a KEM key pair and an Ed25519 key
  pair. The public *bundle* carries both public keys, and
  `MeteorID = SHA256("meteor-nc-v3-id" || bundle)` — self-certifying, so
  `add_peer` and DHT lookups reject a bundle that does not match.
* Every message is an envelope: header (version, type, sender, recipient,
  time, random 128-bit id, hash of the KEM ciphertext, metadata),
  ChaCha20-Poly1305 under a fresh KEM-derived key with the header as
  associated data, and an Ed25519 signature over header and ciphertext.
* Receivers accept only known senders, verify the signature before
  decrypting, and reject timestamps outside a window and repeated
  (sender, id) pairs.
* Ed25519 (via `cryptography`, no fallback) is not post-quantum. A signature
  only has to resist forgery when it is verified, so this does not create a
  harvest-now-decrypt-later risk; the bundle has an algorithm id so ML-DSA
  can be added later.
* The GPU stream DEM is opt-in (`METEOR_NC_GPU_DEM=1`) and must be used on
  both ends.
