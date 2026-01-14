"""
Meteor-Auth: Device-Bound Quantum-Resistant Authentication

This module provides passwordless authentication combining:
- Device binding (2FA: Knowledge + Possession)
- Quantum-resistant cryptography (Meteor-NC)
- Zero-trust server model (no password storage)
- Full P2P integration

Classes:
    MeteorAuth: Client-side authentication
    MeteorAuthServer: Server-side authentication
    UserRecord: User data storage model

Functions:
    verify_device_binding: Verify seed produces expected ID
    generate_recovery_codes: Generate backup codes

Example:
    # Client side
    >>> from meteor_nc.auth import MeteorAuth
    >>> auth = MeteorAuth()
    >>> seed = auth.generate_seed()
    >>> node = auth.login(seed)
    
    # Server side
    >>> from meteor_nc.auth import MeteorAuthServer
    >>> server = MeteorAuthServer()
    >>> token = server.register(meteor_id)
    >>> is_valid = server.authenticate(token, response)

Author: Masamichi Iizumi
License: MIT
"""

from .core import (
    MeteorAuth,
    MeteorAuthServer,
    UserRecord,
    verify_device_binding,
    generate_recovery_codes,
)

__all__ = [
    # Client
    'MeteorAuth',
    
    # Server
    'MeteorAuthServer',
    'UserRecord',
    
    # Utilities
    'verify_device_binding',
    'generate_recovery_codes',
]
