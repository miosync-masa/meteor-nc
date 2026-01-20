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
    from meteor_nc.block.mempool import TxEncryptor, CommitReveal
    
    # Encrypt transaction for sequencer
    encryptor = TxEncryptor(sequencer_pk_blob)
    encrypted_tx = encryptor.encrypt(raw_tx_bytes)
    
    # Commit-reveal flow
    commit_reveal = CommitReveal()
    commit = commit_reveal.create_commit(encrypted_envelope)
    # ... wait for commit confirmation ...
    reveal = commit_reveal.create_reveal(encrypted_envelope)

Updated: 2025-01-20
Version: 0.3.0
"""

from .encrypt import (
    TxEncryptor,
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
