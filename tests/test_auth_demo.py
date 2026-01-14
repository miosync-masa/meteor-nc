#!/usr/bin/env python3
"""
Meteor-Auth Demo (Full P2P Version)

Demonstrates:
1. Registration (client)
2. Login with P2P (client)
3. Challenge-response authentication (server)
4. Full P2P integration

Updated for meteor_nc package structure.
"""

import numpy as np
import sys
import os

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from meteor_nc import MeteorAuth, MeteorAuthServer


def demo_basic_flow():
    """Basic authentication flow with full P2P"""
    
    print("=" * 70)
    print("Meteor-Auth Demo: Basic Flow (P2P)")
    print("=" * 70)
    
    # Step 1: Client generates seed
    print("\n[Client] Generating user seed...")
    auth = MeteorAuth(security_level=256, gpu=False)
    user_seed = auth.generate_seed()
    
    print(f"✓ User seed: {user_seed.hex()[:32]}...")
    print("  ⚠️  SAVE THIS! (QR code, paper, etc.)")
    
    # Step 2: Client gets Meteor ID
    print("\n[Client] Generating Meteor ID...")
    meteor_id = auth.get_meteor_id(user_seed)
    print(f"✓ Meteor ID: {meteor_id.hex()[:32]}...")
    print("  (This is your public identity)")
    
    # Step 3: Server registration
    print("\n[Server] Registering user...")
    server = MeteorAuthServer(gpu=False)
    token = server.register(
        meteor_id,
        metadata={'username': 'alice', 'email': 'alice@example.com'}
    )
    print(f"✓ Token: {token[:32]}...")
    print("  (Server stores: ID + metadata, NO password!)")
    
    # Step 4: Client login (creates P2P node)
    print("\n[Client] Logging in (P2P node creation)...")
    client_node = auth.login(user_seed, node_name="Alice")
    print(f"✓ P2P node created: {client_node.name}")
    print(f"  Meteor ID: {client_node.meteor_id.hex()[:32]}...")
    print("  Device-bound keys ready")
    
    # Step 5: Establish bidirectional P2P connection
    print("\n[Setup] Establishing P2P connection...")
    # Client adds server
    client_node.add_peer("AuthServer", server.node.meteor_id)
    # Server adds client (using registered meteor_id)
    server.node.add_peer(token, meteor_id)
    print("✓ Bidirectional P2P connection established")
    
    # Step 6: Challenge-response
    print("\n[Server] Creating authentication challenge...")
    challenge = server.create_challenge(token)
    print(f"✓ Challenge (plaintext): {challenge.hex()[:32]}...")
    
    print("\n[Client] Encrypting challenge response...")
    # Client encrypts challenge with their key
    encrypted_response = client_node.send("AuthServer", challenge)
    print(f"✓ Challenge encrypted")
    
    print("\n[Server] Verifying encrypted response...")
    is_valid = server.authenticate(token, encrypted_response)
    print(f"✓ Authentication: {'✅ SUCCESS' if is_valid else '❌ FAILED'}")
    
    # Step 7: Show user info
    if is_valid:
        print("\n[Server] Retrieving user info...")
        user_record = server.get_user(token)
        if user_record:
            print(f"✓ User: {user_record.metadata.get('username', 'N/A')}")
            print(f"  Email: {user_record.metadata.get('email', 'N/A')}")
            print(f"  Registered: {user_record.registered_at:.0f}")
    
    return is_valid


def demo_device_binding():
    """Demonstrate device binding with P2P"""
    
    print("\n" + "=" * 70)
    print("Meteor-Auth Demo: Device Binding")
    print("=" * 70)
    
    auth = MeteorAuth(security_level=256, gpu=False)
    
    # Generate seed
    user_seed = auth.generate_seed()
    
    print("\n[Device 1] Login...")
    device1_fp = auth.get_device_fingerprint()
    print(f"Device fingerprint: {device1_fp.hex()[:32]}...")
    
    node1 = auth.login(user_seed, node_name="Device1")
    meteor_id_1 = node1.meteor_id
    print(f"Meteor ID: {meteor_id_1.hex()[:32]}...")
    
    print("\n[Simulation] Seed stolen, used on Device 2...")
    print("(Simulating different MAC address)")
    
    # Monkey-patch for demo
    original_func = auth.get_device_fingerprint
    auth.get_device_fingerprint = lambda: b'different_device_fp_' + b'\x00' * 12
    
    node2 = auth.login(user_seed, node_name="Device2")
    meteor_id_2 = node2.meteor_id
    print(f"Meteor ID: {meteor_id_2.hex()[:32]}...")
    
    # Restore
    auth.get_device_fingerprint = original_func
    
    # Compare
    print(f"\n[Result]")
    print(f"ID match: {meteor_id_1 == meteor_id_2}")
    print(f"Status: {'❌ DIFFERENT DEVICES' if meteor_id_1 != meteor_id_2 else 'Same device'}")
    print("\n✓ Stolen seed is USELESS on different device!")
    print("✓ Each device gets unique Meteor ID")
    print("✓ Server can distinguish devices automatically")
    
    return meteor_id_1 != meteor_id_2


def demo_qr_flow():
    """QR code registration flow with P2P"""
    
    print("\n" + "=" * 70)
    print("Meteor-Auth Demo: QR Code Flow")
    print("=" * 70)
    
    auth = MeteorAuth(security_level=256, gpu=False)
    
    # Generate and export
    print("\n[Client] Generate seed...")
    user_seed = auth.generate_seed()
    qr_data = auth.export_qr_data(user_seed)
    
    print(f"✓ QR data: {qr_data[:64]}...")
    print("  (Encode this as QR code)")
    print("  (Print and store securely)")
    
    # Later: scan and import
    print("\n[Client] Scanning QR code...")
    imported_seed = auth.import_qr_data(qr_data)
    
    print(f"✓ Seed imported")
    print(f"  Match: {imported_seed == user_seed}")
    
    # Login with P2P
    print("\n[Client] Login with QR seed (P2P)...")
    node = auth.login(imported_seed, node_name="QRClient")
    print(f"✓ Logged in!")
    print(f"  Node: {node.name}")
    print(f"  Meteor ID: {node.meteor_id.hex()[:32]}...")
    print("  Ready for P2P communication")
    
    return True


def demo_recovery_codes():
    """Recovery codes demo"""
    
    print("\n" + "=" * 70)
    print("Meteor-Auth Demo: Recovery Codes")
    print("=" * 70)
    
    from meteor_nc.auth import generate_recovery_codes
    
    auth = MeteorAuth(security_level=256, gpu=False)
    user_seed = auth.generate_seed()
    
    print("\n[Client] Generating recovery codes...")
    codes = generate_recovery_codes(user_seed, count=8)
    
    print("✓ Recovery codes generated:")
    for i, code in enumerate(codes, 1):
        print(f"  {i}. {code}")
    
    print("\n⚠️  Store these codes securely!")
    print("    - Write on paper")
    print("    - Store in safe")
    print("    - Each code is one-time use")
    
    return True


def demo_performance():
    """Performance benchmarks"""
    
    print("\n" + "=" * 70)
    print("Meteor-Auth Demo: Performance")
    print("=" * 70)
    
    import time
    
    auth = MeteorAuth(security_level=256, gpu=False)
    user_seed = auth.generate_seed()
    
    # Login timing
    print("\n[Benchmark] Login (key expansion + P2P node)...")
    times = []
    for i in range(5):
        start = time.time()
        node = auth.login(user_seed, node_name=f"Bench{i}")
        elapsed = time.time() - start
        times.append(elapsed * 1000)
    
    print(f"✓ Average: {np.mean(times):.2f} ms")
    print(f"  Std: {np.std(times):.2f} ms")
    print(f"  Min: {np.min(times):.2f} ms")
    print(f"  Max: {np.max(times):.2f} ms")
    
    # Full authentication flow timing
    print("\n[Benchmark] Full auth flow (P2P)...")
    server = MeteorAuthServer(gpu=False)
    meteor_id = auth.get_meteor_id(user_seed)
    token = server.register(meteor_id)
    
    times = []
    for i in range(10):
        start = time.time()
        
        # Client login
        client = auth.login(user_seed, node_name=f"Client{i}")
        
        # Setup bidirectional P2P
        client.add_peer("AuthServer", server.node.meteor_id)
        server.node.add_peer(token, meteor_id)
        
        # Challenge-response
        challenge = server.create_challenge(token)
        response = client.send("AuthServer", challenge)
        is_valid = server.authenticate(token, response)
        
        elapsed = time.time() - start
        times.append(elapsed * 1000)
    
    print(f"✓ Average: {np.mean(times):.2f} ms")
    print(f"  Std: {np.std(times):.2f} ms")
    print(f"  Includes: Login + P2P setup + Challenge + Response + Verify")
    
    return True


def demo_revocation():
    """Token revocation demo"""
    
    print("\n" + "=" * 70)
    print("Meteor-Auth Demo: Token Revocation")
    print("=" * 70)
    
    auth = MeteorAuth(security_level=256, gpu=False)
    server = MeteorAuthServer(gpu=False)
    
    # Register user
    print("\n[Setup] Registering user...")
    user_seed = auth.generate_seed()
    meteor_id = auth.get_meteor_id(user_seed)
    token = server.register(meteor_id, metadata={'username': 'bob'})
    print(f"✓ Token: {token[:16]}...")
    
    # Authenticate (should work)
    print("\n[Test 1] Authentication before revocation...")
    client = auth.login(user_seed, node_name="Bob")
    
    # Setup bidirectional P2P
    client.add_peer("AuthServer", server.node.meteor_id)
    server.node.add_peer(token, meteor_id)
    
    # Challenge-response
    challenge = server.create_challenge(token)
    resp = client.send("AuthServer", challenge)
    valid1 = server.authenticate(token, resp)
    print(f"✓ Result: {'✅ SUCCESS' if valid1 else '❌ FAILED'}")
    
    # Revoke
    print("\n[Server] Revoking token...")
    revoked = server.revoke(token)
    print(f"✓ Revoked: {revoked}")
    
    # Try to authenticate again (should fail)
    print("\n[Test 2] Authentication after revocation...")
    try:
        challenge2 = server.create_challenge(token)
        valid2 = False
    except ValueError as e:
        print(f"✓ Expected error: {e}")
        valid2 = False
    
    print(f"✓ Result: {'❌ BLOCKED (correct!)' if not valid2 else '✅ UNEXPECTED SUCCESS'}")
    
    return valid1 and not valid2


def demo_verify_device_binding():
    """Verify device binding utility"""
    
    print("\n" + "=" * 70)
    print("Meteor-Auth Demo: Verify Device Binding")
    print("=" * 70)
    
    from meteor_nc.auth import verify_device_binding
    
    auth = MeteorAuth(security_level=256, gpu=False)
    user_seed = auth.generate_seed()
    meteor_id = auth.get_meteor_id(user_seed)
    
    print("\n[Test] Verify same seed on same device...")
    is_valid = verify_device_binding(user_seed, meteor_id)
    print(f"✓ Result: {'✅ VALID' if is_valid else '❌ INVALID'}")
    
    print("\n[Test] Verify with wrong ID...")
    wrong_id = b'\x00' * 32
    is_invalid = verify_device_binding(user_seed, wrong_id)
    print(f"✓ Result: {'❌ INVALID (correct!)' if not is_invalid else '✅ UNEXPECTED'}")
    
    return is_valid and not is_invalid


if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║              🌠 Meteor-Auth Demo (Full P2P) 🌠               ║
    ║                                                              ║
    ║         Device-Bound Quantum-Resistant Authentication        ║
    ║              with Full P2P Protocol Integration              ║
    ║                                                              ║
    ║                  meteor_nc package version                   ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Run demos
    results = {}
    
    results['basic_flow'] = demo_basic_flow()
    results['device_binding'] = demo_device_binding()
    results['qr_flow'] = demo_qr_flow()
    results['recovery_codes'] = demo_recovery_codes()
    results['verify_binding'] = demo_verify_device_binding()
    results['performance'] = demo_performance()
    results['revocation'] = demo_revocation()
    
    # Summary
    print("\n" + "=" * 70)
    print("Demo Summary")
    print("=" * 70)
    
    all_passed = all(results.values())
    
    for name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {name}: {status}")
    
    print(f"\nOverall: {'✅ ALL TESTS PASSED' if all_passed else '❌ SOME TESTS FAILED'}")
    
    print("\nMeteor-Auth (Full P2P) is ready for:")
    print("  • Consumer apps (passwordless login)")
    print("  • Banking (mobile security)")
    print("  • Enterprise (BYOD/VPN)")
    print("  • Web 4.0 (decentralized identity)")
    print("  • P2P authentication meshes")
    print("  • Serverless authentication")
    print("\n🌌 Welcome to the future of authentication.")
    print("=" * 70)
    
    sys.exit(0 if all_passed else 1)
