# meteor_nc/block/mempool/__init__.py
"""
Meteor-NC Block Mempool: MEV Protection Layer

Provides encrypted transaction submission and commit-reveal schemes
for MEV (Maximal Extractable Value) protection.

Components:
    TxEncryptor: Encrypt transactions for builder/sequencer
    CommitReveal: Commit-reveal scheme for front-running protection
    ShieldedTx: Shielded transaction wrapper

Target Use Cases:
    - L2/Rollup sequencers
    - Private relays (Flashbots-style)
    - MEV-protected DEX orders

Usage:
    from meteor_nc.block.mempool import TxEncryptor, TxDecryptor, CommitReveal
    
    # Generate or load builder keys
    kem = LWEKEM(n=256)
    pk_bytes, sk_bytes = kem.key_gen()
    
    # Encrypt transaction for builder
    encryptor = TxEncryptor(builder_pk_bytes=pk_bytes, chain_id=1)
    encrypted_tx = encryptor.encrypt(raw_tx_bytes)
    
    # Commit-reveal flow
    commit_reveal = CommitReveal(chain_id=1)
    shielded = commit_reveal.create_shielded(encrypted_tx.envelope)
    # ... submit commit to chain, wait for confirmation ...
    _, reveal_data = commit_reveal.reveal(shielded.commit)
    
    # Builder decrypts
    decryptor = TxDecryptor(pk_bytes=pk_bytes, sk_bytes=sk_bytes, chain_id=1)
    raw_tx = decryptor.decrypt(encrypted_tx.envelope)

Updated: 2025-01-20
Version: 0.3.0
"""

from .encrypt import (
    TxEncryptor,
    TxDecryptor,
    EncryptedTx,
    TxEncryptionError,
)

from .shield import (
    CommitReveal,
    ShieldedTx,
    CommitPhase,
    CommitRevealError,
    CommitMismatchError,
)

__all__ = [
    # Encryption
    "TxEncryptor",
    "TxDecryptor",
    "EncryptedTx",
    "TxEncryptionError",
    
    # Commit-Reveal
    "CommitReveal",
    "ShieldedTx",
    "CommitPhase",
    "CommitRevealError",
    "CommitMismatchError",
]

__version__ = "0.3.0"
