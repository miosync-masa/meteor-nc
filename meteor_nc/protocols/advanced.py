# meteor_nc/protocols/advanced.py
"""
Meteor-Protocol: Advanced Testing & Validation Suite

Comprehensive testing framework for Meteor-Protocol including:
- Large-scale mesh network testing (n > 10 nodes)
- Variable latency simulation (ping diff > 50ms)
- KDF seed persistence and reconnection validation
- Λ (Lambda) stability analysis under network stress

Updated for meteor_protocol.py v2 API
"""

from __future__ import annotations

import numpy as np
import time
import random
import secrets
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

from .meteor_protocol import MeteorNode, MeteorProtocol, MeteorMessage
from ..cryptography.common import GPU_AVAILABLE


# =============================================================================
# 1. Large-Scale Mesh Network Testing
# =============================================================================

class MeteorNetwork:
    """
    Large-scale mesh network for Meteor-Protocol testing.
    
    Supports:
    - Arbitrary number of nodes
    - Full mesh / partial mesh topologies
    - Broadcast testing
    - Λ stability measurement
    
    Example:
        >>> network = MeteorNetwork(num_nodes=20)
        >>> network.create_full_mesh()
        >>> stats = network.run_broadcast_test()
        >>> print(f"Λ stability: {stats['lambda_stability']}")
    """
    
    def __init__(
        self,
        num_nodes: int = 10,
        gpu: bool = True,
        topology: str = 'full_mesh',
    ):
        """Initialize large-scale network."""
        self.num_nodes = num_nodes
        self.gpu = gpu and GPU_AVAILABLE
        self.topology = topology
        
        # Create nodes
        self.nodes: Dict[str, MeteorNode] = {}
        self.node_names: List[str] = []
        
        print(f"\n[MeteorNetwork] Creating {num_nodes} nodes...")
        start = time.time()
        
        for i in range(num_nodes):
            name = f"Node_{i:02d}"
            node = MeteorNode(name=name, gpu=self.gpu)
            self.nodes[name] = node
            self.node_names.append(name)
        
        creation_time = time.time() - start
        print(f"[✓] {num_nodes} nodes created in {creation_time:.2f}s")
        
        # Network statistics
        self.stats = {
            'total_connections': 0,
            'total_messages': 0,
            'total_bytes': 0,
        }
    
    def create_full_mesh(self):
        """
        Create full mesh topology.
        Every node connects to every other node.
        Connections: n(n-1)/2
        """
        print(f"\n[MeteorNetwork] Creating full mesh topology...")
        start = time.time()
        
        connections = 0
        for i in range(self.num_nodes):
            for j in range(i + 1, self.num_nodes):
                node1_name = self.node_names[i]
                node2_name = self.node_names[j]
                
                n1 = self.nodes[node1_name]
                n2 = self.nodes[node2_name]
                
                # Exchange IDs and public keys
                n1.add_peer(node2_name, n2.get_meteor_id(), n2.get_public_key())
                n2.add_peer(node1_name, n1.get_meteor_id(), n1.get_public_key())
                
                connections += 1
        
        mesh_time = time.time() - start
        self.stats['total_connections'] = connections
        
        print(f"[✓] Full mesh created: {connections} connections")
        print(f"    Time: {mesh_time:.2f}s")
    
    def create_ring_topology(self):
        """Create ring topology (each node connects to next)."""
        print(f"\n[MeteorNetwork] Creating ring topology...")
        
        for i in range(self.num_nodes):
            node1_name = self.node_names[i]
            node2_name = self.node_names[(i + 1) % self.num_nodes]
            
            n1 = self.nodes[node1_name]
            n2 = self.nodes[node2_name]
            
            n1.add_peer(node2_name, n2.get_meteor_id(), n2.get_public_key())
            n2.add_peer(node1_name, n1.get_meteor_id(), n1.get_public_key())
        
        self.stats['total_connections'] = self.num_nodes
        print(f"[✓] Ring topology created: {self.num_nodes} connections")
    
    def create_star_topology(self, hub: str = "Node_00"):
        """Create star topology (all nodes connect to hub)."""
        print(f"\n[MeteorNetwork] Creating star topology (hub: {hub})...")
        
        hub_node = self.nodes[hub]
        
        for name in self.node_names:
            if name != hub:
                node = self.nodes[name]
                
                hub_node.add_peer(name, node.get_meteor_id(), node.get_public_key())
                node.add_peer(hub, hub_node.get_meteor_id(), hub_node.get_public_key())
        
        self.stats['total_connections'] = self.num_nodes - 1
        print(f"[✓] Star topology created: {self.num_nodes - 1} connections")
    
    def run_broadcast_test(
        self,
        sender: str = "Node_00",
        message_size: int = 100,
    ) -> Dict:
        """
        Run broadcast test from one node to all others.
        
        Args:
            sender: Sender node name
            message_size: Message size in bytes
            
        Returns:
            dict: Test statistics
        """
        print(f"\n[MeteorNetwork] Running broadcast test...")
        print(f"  Sender: {sender}")
        print(f"  Recipients: {len(self.nodes[sender].peers)}")
        print(f"  Message size: {message_size} bytes")
        
        sender_node = self.nodes[sender]
        message = secrets.token_bytes(message_size)
        
        # Send to all peers
        start = time.time()
        messages_sent = []
        
        for peer_name in sender_node.peers.keys():
            encrypted = sender_node.send(peer_name, message)
            messages_sent.append((peer_name, encrypted))
        
        send_time = time.time() - start
        
        # All recipients receive
        start = time.time()
        messages_received = 0
        
        for peer_name, encrypted in messages_sent:
            peer_node = self.nodes[peer_name]
            try:
                decrypted = peer_node.receive(encrypted)
                if decrypted == message:
                    messages_received += 1
            except Exception as e:
                print(f"    Error receiving at {peer_name}: {e}")
        
        receive_time = time.time() - start
        
        # Calculate statistics
        total_time = send_time + receive_time
        throughput = messages_received / total_time if total_time > 0 else 0
        
        results = {
            'sender': sender,
            'recipients': len(sender_node.peers),
            'messages_sent': len(messages_sent),
            'messages_received': messages_received,
            'success_rate': messages_received / len(messages_sent) if messages_sent else 0,
            'send_time_ms': send_time * 1000,
            'receive_time_ms': receive_time * 1000,
            'total_time_ms': total_time * 1000,
            'throughput_msg_per_sec': throughput,
            'message_size_bytes': message_size,
        }
        
        print(f"\n[Broadcast Results]")
        print(f"  Success rate: {results['success_rate']*100:.1f}%")
        print(f"  Send time: {results['send_time_ms']:.2f}ms")
        print(f"  Receive time: {results['receive_time_ms']:.2f}ms")
        print(f"  Throughput: {results['throughput_msg_per_sec']:.1f} msg/s")
        
        return results
    
    def measure_lambda_stability(self, num_iterations: int = 100) -> Dict:
        """
        Measure Λ stability across the network.
        
        Sends random messages and measures:
        - Encryption/decryption consistency
        - Error rates
        - Performance stability
        """
        print(f"\n[MeteorNetwork] Measuring Λ stability...")
        print(f"  Iterations: {num_iterations}")
        
        errors = []
        encryption_times = []
        decryption_times = []
        
        for iteration in range(num_iterations):
            # Random sender and receiver
            sender_name = random.choice(self.node_names)
            sender_node = self.nodes[sender_name]
            
            if not sender_node.peers:
                continue
            
            recipient_name = random.choice(list(sender_node.peers.keys()))
            recipient_node = self.nodes[recipient_name]
            
            # Random message
            message_size = random.randint(10, 200)
            message = secrets.token_bytes(message_size)
            
            # Send and measure
            start = time.time()
            encrypted = sender_node.send(recipient_name, message)
            enc_time = time.time() - start
            
            start = time.time()
            decrypted = recipient_node.receive(encrypted)
            dec_time = time.time() - start
            
            # Measure error (should be 0 for correct decryption)
            error = 0 if message == decrypted else 1
            
            errors.append(error)
            encryption_times.append(enc_time)
            decryption_times.append(dec_time)
        
        # Analyze stability
        error_rate = np.mean(errors)
        
        enc_time_mean = np.mean(encryption_times) * 1000
        enc_time_std = np.std(encryption_times) * 1000
        
        dec_time_mean = np.mean(decryption_times) * 1000
        dec_time_std = np.std(decryption_times) * 1000
        
        # Λ stability score (lower is better)
        lambda_stability = error_rate + (enc_time_std + dec_time_std) / 1000
        
        results = {
            'iterations': num_iterations,
            'error_rate': error_rate,
            'encryption_time_mean_ms': enc_time_mean,
            'encryption_time_std_ms': enc_time_std,
            'decryption_time_mean_ms': dec_time_mean,
            'decryption_time_std_ms': dec_time_std,
            'lambda_stability_score': lambda_stability,
            'is_stable': error_rate == 0 and lambda_stability < 0.1,
        }
        
        print(f"\n[Λ Stability Analysis]")
        print(f"  Error rate: {error_rate*100:.1f}%")
        print(f"  Encryption time: {enc_time_mean:.2f} ± {enc_time_std:.2f} ms")
        print(f"  Decryption time: {dec_time_mean:.2f} ± {dec_time_std:.2f} ms")
        print(f"  Λ stability score: {lambda_stability:.4f}")
        print(f"  Status: {'✅ STABLE' if results['is_stable'] else '⚠️ UNSTABLE'}")
        
        return results
    
    def get_network_stats(self) -> Dict:
        """Get comprehensive network statistics."""
        total_messages = sum(
            node.stats['messages_sent'] + node.stats['messages_received']
            for node in self.nodes.values()
        )
        
        total_bytes = sum(
            node.stats['bytes_sent'] + node.stats['bytes_received']
            for node in self.nodes.values()
        )
        
        return {
            'num_nodes': self.num_nodes,
            'topology': self.topology,
            'total_connections': self.stats['total_connections'],
            'total_messages': total_messages,
            'total_bytes': total_bytes,
            'avg_peers_per_node': sum(len(n.peers) for n in self.nodes.values()) / self.num_nodes,
        }


# =============================================================================
# 2. Latency Simulation
# =============================================================================

@dataclass
class LatencyProfile:
    """Network latency profile."""
    base_latency_ms: float
    jitter_ms: float
    packet_loss_rate: float = 0.0


class LatencySimulator:
    """
    Simulate variable network latency.
    
    Features:
    - Configurable base latency
    - Jitter simulation
    - Packet loss simulation
    - Resynchronization testing
    
    Example:
        >>> sim = LatencySimulator(base_latency_ms=50, jitter_ms=20)
        >>> sim.add_node_pair(alice, bob)
        >>> results = sim.simulate_communication(num_messages=1000)
    """
    
    def __init__(
        self,
        base_latency_ms: float = 50.0,
        jitter_ms: float = 20.0,
        packet_loss_rate: float = 0.01,
    ):
        """Initialize latency simulator."""
        self.profile = LatencyProfile(
            base_latency_ms=base_latency_ms,
            jitter_ms=jitter_ms,
            packet_loss_rate=packet_loss_rate,
        )
        
        self.node_pairs: List[Tuple[MeteorNode, MeteorNode]] = []
        
        print(f"\n[LatencySimulator] Initialized")
        print(f"  Base latency: {base_latency_ms}ms")
        print(f"  Jitter: ±{jitter_ms}ms")
        print(f"  Packet loss: {packet_loss_rate*100:.1f}%")
    
    def add_node_pair(self, node1: MeteorNode, node2: MeteorNode):
        """Add node pair for simulation."""
        self.node_pairs.append((node1, node2))
        
        # Connect nodes (exchange IDs and public keys)
        node1.add_peer(node2.name, node2.get_meteor_id(), node2.get_public_key())
        node2.add_peer(node1.name, node1.get_meteor_id(), node1.get_public_key())
    
    def _simulate_latency(self) -> float:
        """Generate latency sample."""
        latency = self.profile.base_latency_ms
        latency += random.uniform(-self.profile.jitter_ms, self.profile.jitter_ms)
        return max(0, latency) / 1000  # Convert to seconds
    
    def _should_drop_packet(self) -> bool:
        """Determine if packet should be dropped."""
        return random.random() < self.profile.packet_loss_rate
    
    def simulate_communication(
        self,
        num_messages: int = 100,
        message_size: int = 100,
    ) -> Dict:
        """
        Simulate communication with latency.
        
        Args:
            num_messages: Number of messages to send
            message_size: Message size in bytes
            
        Returns:
            dict: Simulation results
        """
        print(f"\n[LatencySimulator] Running simulation...")
        print(f"  Messages: {num_messages}")
        print(f"  Message size: {message_size} bytes")
        
        if not self.node_pairs:
            raise ValueError("No node pairs added")
        
        node1, node2 = self.node_pairs[0]
        
        messages_sent = 0
        messages_received = 0
        messages_dropped = 0
        latencies = []
        errors = []
        
        start_time = time.time()
        
        for i in range(num_messages):
            # Create message
            message = secrets.token_bytes(message_size)
            
            # Send
            try:
                encrypted = node1.send(node2.name, message)
                messages_sent += 1
                
                # Simulate packet loss
                if self._should_drop_packet():
                    messages_dropped += 1
                    continue
                
                # Simulate latency
                latency = self._simulate_latency()
                time.sleep(latency)
                latencies.append(latency * 1000)
                
                # Receive
                decrypted = node2.receive(encrypted)
                messages_received += 1
                
                # Measure error
                error = 0 if message == decrypted else 1
                errors.append(error)
                
            except Exception as e:
                print(f"  Error in message {i}: {e}")
                continue
        
        total_time = time.time() - start_time
        
        # Calculate statistics
        success_rate = messages_received / messages_sent if messages_sent > 0 else 0
        avg_latency = np.mean(latencies) if latencies else 0
        latency_std = np.std(latencies) if latencies else 0
        error_rate = np.mean(errors) if errors else 0
        
        # Resynchronization score
        resync_score = 1.0 - (latency_std / (avg_latency + 1e-6))
        
        results = {
            'num_messages': num_messages,
            'messages_sent': messages_sent,
            'messages_received': messages_received,
            'messages_dropped': messages_dropped,
            'success_rate': success_rate,
            'avg_latency_ms': avg_latency,
            'latency_std_ms': latency_std,
            'error_rate': error_rate,
            'resynchronization_score': resync_score,
            'total_time_s': total_time,
            'effective_throughput': messages_received / total_time if total_time > 0 else 0,
        }
        
        print(f"\n[Latency Simulation Results]")
        print(f"  Success rate: {success_rate*100:.1f}%")
        print(f"  Messages dropped: {messages_dropped}")
        print(f"  Avg latency: {avg_latency:.2f} ± {latency_std:.2f} ms")
        print(f"  Resync score: {resync_score:.4f}")
        print(f"  Throughput: {results['effective_throughput']:.1f} msg/s")
        
        return results


# =============================================================================
# 3. Session Persistence & Reconnection
# =============================================================================

class SessionManager:
    """
    Test session persistence and KDF seed reconnection.
    
    Validates that:
    - Disconnection → Reconnection preserves identity
    - Same MeteorID is generated from seed
    - Communication continues seamlessly
    
    Example:
        >>> manager = SessionManager()
        >>> results = manager.test_reconnection(seed, num_cycles=10)
    """
    
    def __init__(self):
        """Initialize session manager."""
        print(f"\n[SessionManager] Initialized")
        self.sessions: Dict[str, Dict] = {}
    
    def test_reconnection(
        self,
        original_seed: bytes,
        original_name: str = "TestNode",
        num_cycles: int = 10,
        gpu: bool = True,
    ) -> Dict:
        """
        Test reconnection with KDF seed.
        
        Process:
        1. Create node from seed
        2. Record MeteorID
        3. Destroy node
        4. Recreate from same seed
        5. Verify MeteorID matches
        6. Test communication
        
        Args:
            original_seed: 32-byte seed
            original_name: Node name
            num_cycles: Number of disconnect/reconnect cycles
            gpu: Use GPU acceleration
            
        Returns:
            dict: Reconnection test results
        """
        print(f"\n[SessionManager] Testing reconnection...")
        print(f"  Seed: {original_seed.hex()[:32]}...")
        print(f"  Cycles: {num_cycles}")
        
        # Create first node to get reference ID
        ref_node = MeteorNode(name=original_name, seed=original_seed, gpu=gpu)
        original_id = ref_node.get_meteor_id()
        print(f"  Original MeteorID: {original_id.hex()[:32]}...")
        
        # Create persistent peer for testing
        peer = MeteorNode("TestPeer", gpu=gpu)
        
        id_matches = []
        communication_successes = []
        reconnect_times = []
        
        for cycle in range(num_cycles):
            print(f"\n  Cycle {cycle + 1}/{num_cycles}:")
            
            # Reconnect using seed
            print(f"    [1] Reconnecting from seed...")
            start = time.time()
            
            new_node = MeteorNode(
                name=original_name,
                seed=original_seed,
                gpu=gpu,
            )
            
            reconnect_time = time.time() - start
            reconnect_times.append(reconnect_time)
            
            # Verify ID
            new_id = new_node.get_meteor_id()
            id_match = (new_id == original_id)
            id_matches.append(id_match)
            
            print(f"    [2] ID verification: {'✓ MATCH' if id_match else '✗ MISMATCH'}")
            
            # Test communication
            print(f"    [3] Testing communication...")
            
            # Setup connection
            new_node.add_peer(peer.name, peer.get_meteor_id(), peer.get_public_key())
            peer.add_peer(new_node.name, new_node.get_meteor_id(), new_node.get_public_key())
            
            # Send message
            try:
                message = f"Test message cycle {cycle}".encode('utf-8')
                encrypted = new_node.send(peer.name, message)
                decrypted = peer.receive(encrypted)
                
                comm_success = (decrypted == message)
                communication_successes.append(comm_success)
                
                print(f"        Communication: {'✓ SUCCESS' if comm_success else '✗ FAILED'}")
                
            except Exception as e:
                print(f"        Communication: ✗ FAILED ({e})")
                communication_successes.append(False)
            
            print(f"    Reconnect time: {reconnect_time*1000:.2f}ms")
        
        # Calculate results
        id_consistency = sum(id_matches) / len(id_matches) if id_matches else 0
        comm_success_rate = sum(communication_successes) / len(communication_successes) if communication_successes else 0
        avg_reconnect_time = np.mean(reconnect_times) * 1000
        
        results = {
            'num_cycles': num_cycles,
            'original_seed': original_seed.hex(),
            'original_id': original_id.hex(),
            'id_consistency': id_consistency,
            'communication_success_rate': comm_success_rate,
            'avg_reconnect_time_ms': avg_reconnect_time,
            'all_ids_matched': all(id_matches),
            'all_communications_succeeded': all(communication_successes),
        }
        
        print(f"\n[Reconnection Test Results]")
        print(f"  ID consistency: {id_consistency*100:.1f}%")
        print(f"  Communication success: {comm_success_rate*100:.1f}%")
        print(f"  Avg reconnect time: {avg_reconnect_time:.2f}ms")
        print(f"  Status: {'✅ PERFECT' if results['all_ids_matched'] and results['all_communications_succeeded'] else '⚠️ ISSUES DETECTED'}")
        
        return results


# =============================================================================
# Comprehensive Test Suite
# =============================================================================

def run_comprehensive_tests(
    num_nodes: int = 10,
    gpu: bool = True,
) -> Dict:
    """
    Run all advanced tests.
    
    Args:
        num_nodes: Number of nodes for network test
        gpu: Use GPU acceleration
        
    Returns:
        dict: All test results
    """
    print("=" * 70)
    print("Meteor-Protocol: Advanced Validation Suite")
    print("=" * 70)
    print(f"GPU Available: {GPU_AVAILABLE}")
    
    results = {}
    
    # Test 1: Large-scale mesh network
    print("\n" + "=" * 70)
    print(f"TEST 1: Large-Scale Mesh Network (n={num_nodes})")
    print("=" * 70)
    
    network = MeteorNetwork(num_nodes=num_nodes, gpu=gpu)
    network.create_full_mesh()
    
    broadcast_results = network.run_broadcast_test(message_size=100)
    lambda_results = network.measure_lambda_stability(num_iterations=50)
    network_stats = network.get_network_stats()
    
    results['network'] = {
        'broadcast': broadcast_results,
        'lambda': lambda_results,
        'stats': network_stats,
    }
    
    # Test 2: Variable latency simulation
    print("\n" + "=" * 70)
    print("TEST 2: Variable Latency Simulation")
    print("=" * 70)
    
    alice = MeteorNode("Alice", gpu=gpu)
    bob = MeteorNode("Bob", gpu=gpu)
    
    sim = LatencySimulator(
        base_latency_ms=50,
        jitter_ms=30,
        packet_loss_rate=0.02,
    )
    sim.add_node_pair(alice, bob)
    
    latency_results = sim.simulate_communication(
        num_messages=50,
        message_size=100,
    )
    
    results['latency'] = latency_results
    
    # Test 3: Session persistence
    print("\n" + "=" * 70)
    print("TEST 3: KDF Seed Reconnection")
    print("=" * 70)
    
    test_seed = secrets.token_bytes(32)
    
    manager = SessionManager()
    reconnect_results = manager.test_reconnection(
        original_seed=test_seed,
        num_cycles=5,
        gpu=gpu,
    )
    
    results['reconnection'] = reconnect_results
    
    # Final summary
    print("\n" + "=" * 70)
    print("COMPREHENSIVE TEST RESULTS")
    print("=" * 70)
    
    print(f"\n[Test 1: Large-Scale Mesh]")
    print(f"  ✓ {network_stats['num_nodes']} nodes")
    print(f"  ✓ {network_stats['total_connections']} connections")
    print(f"  ✓ Λ stability: {lambda_results['lambda_stability_score']:.4f}")
    
    print(f"\n[Test 2: Variable Latency]")
    print(f"  ✓ Latency: {latency_results['avg_latency_ms']:.1f}ms")
    print(f"  ✓ Success rate: {latency_results['success_rate']*100:.1f}%")
    
    print(f"\n[Test 3: Session Persistence]")
    print(f"  ✓ ID consistency: {reconnect_results['id_consistency']*100:.1f}%")
    print(f"  ✓ Reconnect time: {reconnect_results['avg_reconnect_time_ms']:.2f}ms")
    
    all_passed = (
        lambda_results['is_stable'] and
        latency_results['success_rate'] > 0.9 and
        reconnect_results['all_ids_matched']
    )
    
    results['all_passed'] = all_passed
    
    print("\n" + "=" * 70)
    print(f"{'✅ ALL TESTS PASSED' if all_passed else '⚠️ SOME TESTS FAILED'}")
    print("=" * 70)
    
    return results


# =============================================================================
# Export
# =============================================================================

__all__ = [
    'MeteorNetwork',
    'LatencySimulator',
    'LatencyProfile',
    'SessionManager',
    'run_comprehensive_tests',
]
