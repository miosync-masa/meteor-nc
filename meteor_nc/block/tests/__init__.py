# meteor_nc/block/tests/__init__.py
"""
Meteor-NC Block: Test Suite

Integration tests for the complete block module.

Run all tests:
    python -m meteor_nc.block.tests.test_integration

Test coverage:
    - Wallet-to-Wallet messaging (MetaMask ↔ WalletConnect)
    - Registry-based key discovery
    - MEV-protected transaction submission
    - Commit-reveal scheme
    - Multi-party communication

Updated: 2025-01-20
"""

from .test_integration import run_tests

__all__ = ["run_tests"]
