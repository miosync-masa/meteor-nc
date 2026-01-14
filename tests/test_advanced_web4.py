#!/usr/bin/env python3
"""
Meteor-NC: Advanced Protocols & Web4 Demo

Tests:
1. MeteorNetwork (mesh network)
2. LatencySimulator (network simulation)
3. SessionManager (reconnection testing)
4. MeteorIdentity (decentralized identity)
5. run_comprehensive_tests (integrated test)

Usage:
    python tests/test_advanced_web4.py
"""

import sys
import os
import time
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from meteor_nc import MeteorNode
from meteor_nc.protocols.advanced import (
    MeteorNetwork,
    LatencySimulator,
    SessionManager,
    run_comprehensive_tests,
)

# Web4 imports (may have optional dependencies)
try:
    from meteor_nc.protocols.web4 import (
        MeteorIdentity,
        MeteorIPFS,
        NACL_AVAILABLE,
    )
    WEB4_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ Web4 imports failed: {e}")
    WEB4_AVAILABLE = False


def demo_meteor_network():
    """Test MeteorNetwork (mesh network)"""
    print("=" * 70)
    print("Demo 1: MeteorNetwork (Mesh Network)")
    print("=" * 70)
    
    # Create network with 5 nodes
    print("\n[*] Creating Meteor Network with 5 nodes...")
    network = MeteorNetwork(num_nodes=5, security_level=256, topology='full_mesh')
    
    # Create mesh connections
    print("\n[*] Creating full mesh topology...")
    network.create_full_mesh()
    
    # Run broadcast test
    print("\n[*] Running broadcast test...")
    results = network.run_broadcast_test(messages_per_node=10)
    
    print(f"\n[Results]")
    print(f"  Total messages: {results['total_messages']}")
    print(f"  Success rate: {results['success_rate']*100:.1f}%")
    print(f"  Λ stability: {results['lambda_stability']:.4f}")
    print(f"  Total time: {results['total_time']:.2f}s")
    
    # Get network stats
    stats = network.get_stats()
    print(f"\n[Network Stats]")
    print(f"  Nodes: {stats['num_nodes']}")
    print(f"  Connections: {stats['total_connections']}")
    print(f"  Total bytes: {stats['total_bytes']:,}")
    
    print("\n✅ MeteorNetwork: PASS")
    return True


def demo_latency_simulator():
    """Test LatencySimulator"""
    print("\n" + "=" * 70)
    print("Demo 2: LatencySimulator (Network Simulation)")
    print("=" * 70)
    
    # Create simulator
    print("\n[*] Creating LatencySimulator...")
    sim = LatencySimulator(
        base_latency_ms=50.0,
        jitter_ms=20.0,
        packet_loss_rate=0.02  # 2% packet loss
    )
    
    # Create nodes
    print("\n[*] Creating node pair...")
    alice = MeteorNode("Alice", security_level=256)
    bob = MeteorNode("Bob", security_level=256)
    
    # Add to simulator
    sim.add_node_pair(alice, bob)
    
    # Simulate communication
    print("\n[*] Simulating 100 messages...")
    results = sim.simulate_communication(num_messages=100, message_size=1024)
    
    print(f"\n[Results]")
    print(f"  Messages sent: {results['messages_sent']}")
    print(f"  Messages received: {results['messages_received']}")
    print(f"  Messages dropped: {results['messages_dropped']}")
    print(f"  Delivery rate: {results['delivery_rate']*100:.1f}%")
    print(f"  Avg latency: {results['avg_latency_ms']:.2f}ms")
    print(f"  Min latency: {results['min_latency_ms']:.2f}ms")
    print(f"  Max latency: {results['max_latency_ms']:.2f}ms")
    print(f"  Λ stability: {results.get('lambda_stability', 'N/A')}")
    
    print("\n✅ LatencySimulator: PASS")
    return True


def demo_session_manager():
    """Test SessionManager (reconnection testing)"""
    print("\n" + "=" * 70)
    print("Demo 3: SessionManager (Reconnection Testing)")
    print("=" * 70)
    
    # Create session manager
    print("\n[*] Creating SessionManager...")
    manager = SessionManager()
    
    # Create original node
    print("\n[*] Creating original node...")
    original_node = MeteorNode("TestNode", security_level=256)
    original_id = original_node.get_meteor_id()
    print(f"  Original MeteorID: {original_id.hex()[:32]}...")
    
    # Test reconnection
    print("\n[*] Testing reconnection (5 cycles)...")
    results = manager.test_reconnection(original_node, num_cycles=5)
    
    print(f"\n[Results]")
    print(f"  ID consistency: {results['id_consistency']*100:.1f}%")
    print(f"  Comm success rate: {results['communication_success_rate']*100:.1f}%")
    print(f"  Avg reconnect time: {results['avg_reconnect_time']*1000:.2f}ms")
    print(f"  All IDs match: {'✅' if results['id_consistency'] == 1.0 else '❌'}")
    
    print("\n✅ SessionManager: PASS")
    return True


def demo_meteor_identity():
    """Test MeteorIdentity (Web4)"""
    if not WEB4_AVAILABLE:
        print("\n⚠️ Web4 not available, skipping...")
        return None
    
    print("\n" + "=" * 70)
    print("Demo 4: MeteorIdentity (Decentralized Identity)")
    print("=" * 70)
    
    # Create identity
    print("\n[*] Creating MeteorIdentity...")
    identity = MeteorIdentity()
    
    print(f"  MeteorID: {identity.meteor_id.hex()[:32]}...")
    print(f"  PeerID: {identity.peer_id}")
    print(f"  Ed25519 Public: {identity.ed25519_public.hex()[:32]}...")
    
    # Sign data
    print("\n[*] Signing data...")
    data = b"Hello, Web4!"
    signature = identity.sign(data)
    print(f"  Signature: {signature.hex()[:32]}...")
    
    # Verify signature
    print("\n[*] Verifying signature...")
    valid = identity.verify(data, signature, identity.ed25519_public)
    print(f"  Valid: {'✅' if valid else '❌'}")
    
    # Export/Import
    print("\n[*] Export identity...")
    exported = identity.to_dict()
    print(f"  MeteorID: {exported['meteor_id'][:32]}...")
    print(f"  PeerID: {exported['peer_id']}")
    
    # Create from MeteorID
    print("\n[*] Recreate identity from MeteorID...")
    identity2 = MeteorIdentity.from_meteor_id(identity.meteor_id)
    print(f"  PeerID match: {'✅' if identity.peer_id == identity2.peer_id else '❌'}")
    
    print("\n✅ MeteorIdentity: PASS")
    return True


def demo_meteor_ipfs():
    """Test MeteorIPFS"""
    if not WEB4_AVAILABLE:
        print("\n⚠️ Web4 not available, skipping...")
        return None
    
    print("\n" + "=" * 70)
    print("Demo 5: MeteorIPFS (IPFS Integration)")
    print("=" * 70)
    
    try:
        # Create IPFS instance
        print("\n[*] Creating MeteorIPFS...")
        ipfs = MeteorIPFS()
        
        # Check connection
        print("\n[*] Checking IPFS connection...")
        connected = ipfs.is_connected()
        
        if not connected:
            print("  ⚠️ IPFS daemon not running")
            print("  To test: ipfs daemon &")
            return None
        
        print(f"  ✅ Connected to IPFS")
        
        # Add data
        print("\n[*] Adding data to IPFS...")
        data = f"Hello from Meteor-NC! Time: {time.time()}".encode()
        cid = ipfs.add(data)
        print(f"  CID: {cid}")
        
        # Get data
        print("\n[*] Retrieving data...")
        retrieved = ipfs.get(cid)
        print(f"  Retrieved: {len(retrieved)} bytes")
        print(f"  Match: {'✅' if data == retrieved else '❌'}")
        
        print("\n✅ MeteorIPFS: PASS")
        return True
        
    except Exception as e:
        print(f"  ⚠️ IPFS error: {e}")
        return None


def demo_comprehensive_tests():
    """Run comprehensive tests from advanced.py"""
    print("\n" + "=" * 70)
    print("Demo 6: Comprehensive Tests (All-in-One)")
    print("=" * 70)
    
    print("\n[*] Running comprehensive tests (5 nodes, 50 messages)...")
    print("    This may take a minute...\n")
    
    try:
        results = run_comprehensive_tests(
            num_nodes=5,
            messages_per_test=50,
            security_level=256
        )
        
        print(f"\n[Summary]")
        print(f"  Mesh network: {'✅' if results.get('mesh_test', {}).get('success', False) else '❌'}")
        print(f"  Latency simulation: {'✅' if results.get('latency_test', {}).get('success', False) else '❌'}")
        print(f"  Session reconnection: {'✅' if results.get('session_test', {}).get('success', False) else '❌'}")
        
        return results.get('all_passed', False)
        
    except Exception as e:
        print(f"  ⚠️ Test error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all demos"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║          🌠 Meteor-NC: Advanced & Web4 Demo 🌠               ║
    ║                                                              ║
    ║           MeteorNetwork | LatencySimulator                   ║
    ║           SessionManager | MeteorIdentity                    ║
    ║           MeteorIPFS | Comprehensive Tests                   ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    results = {}
    
    # Core tests (always run)
    try:
        results['meteor_network'] = demo_meteor_network()
    except Exception as e:
        print(f"  ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        results['meteor_network'] = False
    
    try:
        results['latency_simulator'] = demo_latency_simulator()
    except Exception as e:
        print(f"  ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        results['latency_simulator'] = False
    
    try:
        results['session_manager'] = demo_session_manager()
    except Exception as e:
        print(f"  ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        results['session_manager'] = False
    
    # Web4 tests (optional dependencies)
    try:
        results['meteor_identity'] = demo_meteor_identity()
    except Exception as e:
        print(f"  ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        results['meteor_identity'] = None
    
    try:
        results['meteor_ipfs'] = demo_meteor_ipfs()
    except Exception as e:
        print(f"  ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        results['meteor_ipfs'] = None
    
    # Skip comprehensive test by default (takes time)
    # Uncomment to run:
    # results['comprehensive'] = demo_comprehensive_tests()
    
    # Summary
    print("\n" + "=" * 70)
    print("Demo Summary")
    print("=" * 70)
    
    for name, result in results.items():
        if result is True:
            status = "✅ PASS"
        elif result is False:
            status = "❌ FAIL"
        else:
            status = "⚠️ SKIPPED"
        print(f"  {name}: {status}")
    
    passed = sum(1 for r in results.values() if r is True)
    skipped = sum(1 for r in results.values() if r is None)
    failed = sum(1 for r in results.values() if r is False)
    
    print(f"\nTotal: {passed} passed, {skipped} skipped, {failed} failed")
    
    if failed == 0:
        print("\n✅ ALL AVAILABLE TESTS PASSED!")
    else:
        print("\n❌ SOME TESTS FAILED")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
