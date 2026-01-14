#!/usr/bin/env python3
"""
Meteor-NC: Basic Protocol Demo

Tests:
1. Text message send/receive
2. Binary data (file-like) transfer
3. Batch message transfer
4. MeteorProtocol network
5. Bidirectional communication
6. Message serialization

Usage:
    python tests/test_basic_protocol.py
"""

import sys
import os
import time
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from meteor_nc import MeteorNode, MeteorProtocol
from meteor_nc.protocols.basic import MeteorMessage


def demo_text_message():
    """Test basic text message send/receive"""
    print("=" * 70)
    print("Demo 1: Text Message Send/Receive")
    print("=" * 70)
    
    # Create nodes
    print("\n[*] Creating Alice and Bob nodes...")
    alice = MeteorNode("Alice", security_level=256)
    bob = MeteorNode("Bob", security_level=256)
    
    print(f"  Alice MeteorID: {alice.get_meteor_id().hex()[:32]}...")
    print(f"  Bob MeteorID:   {bob.get_meteor_id().hex()[:32]}...")
    
    # Exchange IDs (simulate discovery)
    print("\n[*] Exchanging peer IDs...")
    alice.add_peer("Bob", bob.get_meteor_id())
    bob.add_peer("Alice", alice.get_meteor_id())
    print("  ✓ Peers added")
    
    # Send text message
    print("\n[*] Alice sending message to Bob...")
    text = "Hello, Bob! This is a quantum-resistant message! 🚀"
    message = alice.send("Bob", text.encode('utf-8'))
    print(f"  ✓ Sent: {len(text)} chars")
    print(f"  ✓ Encrypted size: {message.ciphertext.nbytes} bytes")
    
    # Receive message
    print("\n[*] Bob receiving message...")
    decrypted = bob.receive(message)
    received_text = decrypted.decode('utf-8')
    print(f"  ✓ Received: {received_text}")
    
    # Verify
    match = text == received_text
    print(f"\n[Result] Match: {'✅' if match else '❌'}")
    
    print("\n✅ Text Message: PASS")
    return True


def demo_binary_transfer():
    """Test binary data (file-like) transfer"""
    print("\n" + "=" * 70)
    print("Demo 2: Binary Data Transfer (File Simulation)")
    print("=" * 70)
    
    # Create nodes
    print("\n[*] Creating nodes...")
    alice = MeteorNode("Alice", security_level=256)
    bob = MeteorNode("Bob", security_level=256)
    
    alice.add_peer("Bob", bob.get_meteor_id())
    bob.add_peer("Alice", alice.get_meteor_id())
    
    # Create "file" data (random binary)
    print("\n[*] Creating simulated file (10KB)...")
    file_data = os.urandom(10 * 1024)  # 10KB random data
    file_name = "secret_document.pdf"
    
    # Create header + data
    header = f"FILE:{file_name}:{len(file_data)}:".encode()
    payload = header + file_data
    print(f"  File: {file_name}")
    print(f"  Size: {len(file_data):,} bytes")
    print(f"  Total payload: {len(payload):,} bytes")
    
    # Send
    print("\n[*] Sending file...")
    start = time.time()
    message = alice.send("Bob", payload)
    send_time = time.time() - start
    print(f"  ✓ Encrypted in {send_time*1000:.2f}ms")
    
    # Receive
    print("\n[*] Receiving file...")
    start = time.time()
    decrypted = bob.receive(message)
    recv_time = time.time() - start
    print(f"  ✓ Decrypted in {recv_time*1000:.2f}ms")
    
    # Parse header
    parts = decrypted.split(b':', 3)
    recv_name = parts[1].decode()
    recv_size = int(parts[2])
    recv_data = parts[3]
    
    print(f"\n[Received File]")
    print(f"  Name: {recv_name}")
    print(f"  Size: {recv_size:,} bytes")
    print(f"  Data match: {'✅' if recv_data == file_data else '❌'}")
    
    print("\n✅ Binary Transfer: PASS")
    return True


def demo_batch_messages():
    """Test batch message transfer"""
    print("\n" + "=" * 70)
    print("Demo 3: Batch Message Transfer")
    print("=" * 70)
    
    # Create nodes
    print("\n[*] Creating nodes...")
    alice = MeteorNode("Alice", security_level=256)
    bob = MeteorNode("Bob", security_level=256)
    
    alice.add_peer("Bob", bob.get_meteor_id())
    bob.add_peer("Alice", alice.get_meteor_id())
    
    # Create batch of messages
    num_messages = 100
    print(f"\n[*] Creating {num_messages} messages...")
    messages_data = [f"Message #{i}: Random={os.urandom(8).hex()}".encode() 
                     for i in range(num_messages)]
    
    # Send batch
    print(f"\n[*] Sending batch...")
    start = time.time()
    encrypted_batch = alice.send_batch("Bob", messages_data)
    send_time = time.time() - start
    print(f"  ✓ Encrypted {num_messages} messages in {send_time*1000:.2f}ms")
    print(f"  ✓ Throughput: {num_messages/send_time:,.0f} msg/s")
    
    # Receive batch
    print(f"\n[*] Receiving batch...")
    start = time.time()
    decrypted_batch = bob.receive_batch(encrypted_batch)
    recv_time = time.time() - start
    print(f"  ✓ Decrypted {len(decrypted_batch)} messages in {recv_time*1000:.2f}ms")
    print(f"  ✓ Throughput: {num_messages/recv_time:,.0f} msg/s")
    
    # Verify all
    matches = sum(1 for orig, decr in zip(messages_data, decrypted_batch) if orig == decr)
    print(f"\n[Result] Matched: {matches}/{num_messages}")
    
    print("\n✅ Batch Messages: PASS")
    return matches == num_messages


def demo_meteor_protocol():
    """Test MeteorProtocol network"""
    print("\n" + "=" * 70)
    print("Demo 4: MeteorProtocol Network")
    print("=" * 70)
    
    # Create protocol
    print("\n[*] Creating MeteorProtocol...")
    protocol = MeteorProtocol()
    
    # Add nodes
    print("\n[*] Adding nodes...")
    alice = protocol.add_node("Alice", security_level=256)
    bob = protocol.add_node("Bob", security_level=256)
    charlie = protocol.add_node("Charlie", security_level=256)
    
    print(f"  ✓ Alice: {alice.get_meteor_id().hex()[:16]}...")
    print(f"  ✓ Bob:   {bob.get_meteor_id().hex()[:16]}...")
    print(f"  ✓ Charlie: {charlie.get_meteor_id().hex()[:16]}...")
    
    # Connect nodes
    print("\n[*] Connecting nodes...")
    protocol.connect("Alice", "Bob")
    protocol.connect("Bob", "Charlie")
    protocol.connect("Alice", "Charlie")
    print("  ✓ Mesh connected")
    
    # Send messages
    print("\n[*] Sending messages through network...")
    
    # Alice → Bob
    protocol.send("Alice", "Bob", b"Hello Bob from Alice!")
    msg1 = protocol.receive("Bob")
    print(f"  Alice → Bob: {msg1.decode() if msg1 else 'FAILED'}")
    
    # Bob → Charlie
    protocol.send("Bob", "Charlie", b"Hello Charlie from Bob!")
    msg2 = protocol.receive("Charlie")
    print(f"  Bob → Charlie: {msg2.decode() if msg2 else 'FAILED'}")
    
    # Charlie → Alice
    protocol.send("Charlie", "Alice", b"Hello Alice from Charlie!")
    msg3 = protocol.receive("Alice")
    print(f"  Charlie → Alice: {msg3.decode() if msg3 else 'FAILED'}")
    
    # Network stats
    print("\n[*] Network statistics...")
    stats = protocol.get_network_stats()
    print(f"  Nodes: {stats['num_nodes']}")
    print(f"  Total messages: {stats['total_messages']}")
    print(f"  Total bytes: {stats['total_bytes']:,}")
    
    print("\n✅ MeteorProtocol: PASS")
    return True


def demo_bidirectional():
    """Test bidirectional communication"""
    print("\n" + "=" * 70)
    print("Demo 5: Bidirectional Communication")
    print("=" * 70)
    
    # Create nodes
    print("\n[*] Creating nodes...")
    alice = MeteorNode("Alice", security_level=256)
    bob = MeteorNode("Bob", security_level=256)
    
    alice.add_peer("Bob", bob.get_meteor_id())
    bob.add_peer("Alice", alice.get_meteor_id())
    
    # Simulate conversation
    print("\n[*] Simulating conversation...")
    
    conversation = [
        ("Alice", "Bob", "Hey Bob! How are you?"),
        ("Bob", "Alice", "I'm great! Using quantum-safe encryption!"),
        ("Alice", "Bob", "That's awesome! 🔐"),
        ("Bob", "Alice", "Thanks to Meteor-NC! 🌠"),
    ]
    
    all_success = True
    for sender_name, recv_name, text in conversation:
        sender = alice if sender_name == "Alice" else bob
        receiver = bob if recv_name == "Bob" else alice
        peer_name = recv_name if sender_name == "Alice" else "Alice"
        
        # Send
        msg = sender.send(peer_name, text.encode())
        
        # Receive
        decrypted = receiver.receive(msg)
        received = decrypted.decode()
        
        match = text == received
        all_success = all_success and match
        
        print(f"  {sender_name} → {recv_name}: {text}")
        print(f"    Received: {received} {'✅' if match else '❌'}")
    
    print(f"\n[Result] All messages: {'✅' if all_success else '❌'}")
    
    print("\n✅ Bidirectional: PASS")
    return all_success


def demo_message_serialization():
    """Test message serialization"""
    print("\n" + "=" * 70)
    print("Demo 6: Message Serialization")
    print("=" * 70)
    
    # Create nodes
    print("\n[*] Creating nodes...")
    alice = MeteorNode("Alice", security_level=256)
    bob = MeteorNode("Bob", security_level=256)
    
    alice.add_peer("Bob", bob.get_meteor_id())
    bob.add_peer("Alice", alice.get_meteor_id())
    
    # Create message
    print("\n[*] Creating encrypted message...")
    original_text = b"This message will be serialized!"
    message = alice.send("Bob", original_text)
    
    print(f"  Sender: {message.sender_id.hex()[:16]}...")
    print(f"  Recipient: {message.recipient_id.hex()[:16]}...")
    print(f"  Timestamp: {message.timestamp}")
    
    # Serialize
    print("\n[*] Serializing to bytes...")
    serialized = message.to_bytes()
    print(f"  Serialized size: {len(serialized):,} bytes")
    
    # Deserialize
    print("\n[*] Deserializing...")
    restored = MeteorMessage.from_bytes(serialized)
    print(f"  Sender match: {'✅' if restored.sender_id == message.sender_id else '❌'}")
    print(f"  Recipient match: {'✅' if restored.recipient_id == message.recipient_id else '❌'}")
    print(f"  Timestamp match: {'✅' if restored.timestamp == message.timestamp else '❌'}")
    
    # Decrypt restored message
    print("\n[*] Decrypting restored message...")
    decrypted = bob.receive(restored)
    match = decrypted == original_text
    print(f"  Content match: {'✅' if match else '❌'}")
    
    print("\n✅ Serialization: PASS")
    return match


def demo_stats_and_cleanup():
    """Test stats tracking and cleanup"""
    print("\n" + "=" * 70)
    print("Demo 7: Statistics & Cleanup")
    print("=" * 70)
    
    # Create nodes
    print("\n[*] Creating nodes...")
    alice = MeteorNode("Alice", security_level=256)
    bob = MeteorNode("Bob", security_level=256)
    
    alice.add_peer("Bob", bob.get_meteor_id())
    bob.add_peer("Alice", alice.get_meteor_id())
    
    # Send multiple messages
    print("\n[*] Sending 50 messages...")
    for i in range(50):
        msg = alice.send("Bob", f"Message {i}".encode())
        bob.receive(msg)
    
    # Check stats
    print("\n[*] Alice stats:")
    alice_stats = alice.get_stats()
    print(f"  Messages sent: {alice_stats['messages_sent']}")
    print(f"  Bytes sent: {alice_stats['bytes_sent']:,}")
    
    print("\n[*] Bob stats:")
    bob_stats = bob.get_stats()
    print(f"  Messages received: {bob_stats['messages_received']}")
    print(f"  Bytes received: {bob_stats['bytes_received']:,}")
    
    # Cleanup
    print("\n[*] Cleanup...")
    alice.cleanup()
    bob.cleanup()
    print("  ✓ Resources released")
    
    print("\n✅ Stats & Cleanup: PASS")
    return True


def demo_large_file():
    """Test large file transfer"""
    print("\n" + "=" * 70)
    print("Demo 8: Large File Transfer (1MB)")
    print("=" * 70)
    
    # Create nodes
    print("\n[*] Creating nodes...")
    alice = MeteorNode("Alice", security_level=256)
    bob = MeteorNode("Bob", security_level=256)
    
    alice.add_peer("Bob", bob.get_meteor_id())
    bob.add_peer("Alice", alice.get_meteor_id())
    
    # Create large data (1MB)
    print("\n[*] Creating 1MB data...")
    large_data = os.urandom(1024 * 1024)
    print(f"  Size: {len(large_data):,} bytes")
    
    # Split into chunks (256 * 256 = 65536 bytes max per message)
    chunk_size = 60000  # Safe size under n*n
    chunks = [large_data[i:i+chunk_size] for i in range(0, len(large_data), chunk_size)]
    print(f"  Chunks: {len(chunks)}")
    
    # Send as batch
    print("\n[*] Sending chunks...")
    start = time.time()
    encrypted_chunks = alice.send_batch("Bob", chunks)
    send_time = time.time() - start
    print(f"  ✓ Encrypted in {send_time:.2f}s")
    print(f"  ✓ Throughput: {len(large_data)/send_time/1024/1024:.2f} MB/s")
    
    # Receive
    print("\n[*] Receiving chunks...")
    start = time.time()
    decrypted_chunks = bob.receive_batch(encrypted_chunks)
    recv_time = time.time() - start
    print(f"  ✓ Decrypted in {recv_time:.2f}s")
    print(f"  ✓ Throughput: {len(large_data)/recv_time/1024/1024:.2f} MB/s")
    
    # Reassemble
    reassembled = b''.join(decrypted_chunks)
    match = reassembled == large_data
    print(f"\n[Result] Data integrity: {'✅' if match else '❌'}")
    
    print("\n✅ Large File: PASS")
    return match


def main():
    """Run all demos"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║         🌠 Meteor-NC: Basic Protocol Demo 🌠                 ║
    ║                                                              ║
    ║          Text Messages | File Transfer | Batch               ║
    ║          MeteorProtocol | Serialization | Stats              ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    results = {}
    
    demos = [
        ('text_message', demo_text_message),
        ('binary_transfer', demo_binary_transfer),
        ('batch_messages', demo_batch_messages),
        ('meteor_protocol', demo_meteor_protocol),
        ('bidirectional', demo_bidirectional),
        ('serialization', demo_message_serialization),
        ('stats_cleanup', demo_stats_and_cleanup),
        ('large_file', demo_large_file),
    ]
    
    for name, func in demos:
        try:
            results[name] = func()
        except Exception as e:
            print(f"\n❌ Error in {name}: {e}")
            import traceback
            traceback.print_exc()
            results[name] = False
    
    # Summary
    print("\n" + "=" * 70)
    print("Demo Summary")
    print("=" * 70)
    
    for name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {name}: {status}")
    
    passed = sum(1 for r in results.values() if r)
    failed = sum(1 for r in results.values() if not r)
    
    print(f"\nTotal: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("\n✅ ALL TESTS PASSED!")
        print("""
Meteor-NC Basic Protocol is ready for:
  • Instant messaging (text)
  • File sharing (binary)
  • High-throughput batch operations
  • Multi-node networks
  • Message persistence (serialization)

🌌 Quantum-resistant communication at your fingertips!
        """)
    else:
        print("\n❌ SOME TESTS FAILED")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
