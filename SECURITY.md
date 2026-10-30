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
* The insecure GPU batch classes are disabled. A GPU port of the v3 core is
  future work.

## Remaining limitations

* Pure Python/NumPy: no constant-time guarantees. Research and reference
  use only.
* Sizes grow to FrodoKEM's: public key ~9.6 / 15.6 / 21.5 KB and ciphertext
  ~9.8 / 15.8 / 21.7 KB for L1 / L3 / L5. The small v2 sizes were a
  consequence of the broken construction.
