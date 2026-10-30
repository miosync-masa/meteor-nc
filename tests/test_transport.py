"""
TCP transport and signed address records (protocols/transport.py).

Includes a test with a second OS process (tests/peer_process.py) talking to
this one over localhost TCP in both directions.
"""
import asyncio
import dataclasses
import logging
import os
import struct
import sys

import pytest

from meteor_nc.protocols.envelope import EnvelopeError, MeteorIdentity
from meteor_nc.protocols.transport import (
    FRAME_MAGIC, TCPTransport, make_address_record, parse_address_record,
)
from meteor_nc.protocols.web4 import MeteorWeb4Node

logging.disable(logging.WARNING)
HERE = os.path.dirname(os.path.abspath(__file__))


def test_address_record_roundtrip_and_forgery():
    alice, mallory = MeteorIdentity(), MeteorIdentity()
    rec = make_address_record(alice, ["tcp://127.0.0.1:4000"])
    mid, bundle, addrs, _ = parse_address_record(rec)
    assert (mid, bundle, addrs) == (alice.meteor_id, alice.bundle, ["tcp://127.0.0.1:4000"])
    # redirect Alice's MeteorID to Mallory's address: signature breaks
    forged = rec.replace(b"127.0.0.1:4000", b"6.6.6.666:4000")
    with pytest.raises(EnvelopeError):
        parse_address_record(forged)
    # Mallory signs a record claiming Alice's MeteorID: bundle/ID mismatch
    m = bytearray(make_address_record(mallory, ["tcp://6.6.6.6:1"]))
    m[5:37] = alice.meteor_id
    with pytest.raises(EnvelopeError):
        parse_address_record(bytes(m))
    with pytest.raises(EnvelopeError):
        parse_address_record(rec, max_age_s=-1)          # too old
    with pytest.raises(EnvelopeError):
        parse_address_record(rec[:-5])


def test_tcp_roundtrip_between_nodes_in_one_process():
    async def run():
        a = MeteorWeb4Node("Alice", local_delivery=False)
        b = MeteorWeb4Node("Bob", local_delivery=False)
        await a.start_tcp(); await b.start_tcp()
        a.add_peer_from_record("Bob", b.get_address_record())
        b.add_peer_from_record("Alice", a.get_address_record())
        inbox_a, inbox_b = [], []

        async def ha(s, d, e): inbox_a.append((s, d))
        async def hb(s, d, e): inbox_b.append((s, d))
        a.on_message(ha); b.on_message(hb)
        assert await a.send_text("Bob", "over tcp")
        assert await b.send_binary("Alice", b"\x00" * 70_000)
        assert inbox_b == [("Alice", b"over tcp")] and inbox_a == [("Bob", b"\x00" * 70_000)]
        await a.stop(); await b.stop()
        assert not await a.send_text("Bob", "bob is gone")
    asyncio.run(run())


def test_tcp_rejects_garbage_oversize_and_replays():
    async def run():
        a = MeteorWeb4Node("Alice", local_delivery=False)
        b = MeteorWeb4Node("Bob", local_delivery=False)
        addr = await b.start_tcp()
        b.add_peer_from_record("Alice", a.get_address_record())
        b.tcp.max_frame = 1 << 20
        assert not await TCPTransport.send(addr, b"garbage")
        host, port = addr[6:].rsplit(":", 1)
        r, w = await asyncio.open_connection(host, int(port))
        w.write(FRAME_MAGIC + struct.pack(">I", 1 << 30)); await w.drain()
        assert await r.read(1) == b"\x00"
        w.close()
        from meteor_nc.protocols.envelope import seal
        env = seal(a.identity._core, "text", b"once", recipient_id=b.meteor_id,
                   recipient_bundle=b.get_public_key()).to_bytes()
        assert await TCPTransport.send(addr, env)
        assert not await TCPTransport.send(addr, env)            # replay
        await b.stop()
    asyncio.run(run())


def test_two_os_processes_talk_over_tcp():
    """Alice (this process) <-> Bob (tests/peer_process.py) over localhost."""
    async def run():
        alice = MeteorWeb4Node("Alice", local_delivery=False)
        await alice.start_tcp()
        replies = asyncio.Queue()

        async def h(sender, data, env):
            await replies.put((sender, data.decode()))
        alice.on_message(h)
        proc = await asyncio.create_subprocess_exec(
            sys.executable, os.path.join(HERE, "peer_process.py"),
            alice.get_address_record().hex(),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            line = (await asyncio.wait_for(proc.stdout.readline(), 120)).decode().split()
            assert line[0] == "RECORD", line
            bob_id = alice.add_peer_from_record("Bob", bytes.fromhex(line[1]))
            assert bob_id != alice.meteor_id
            assert await alice.send_text("Bob", "ping from another process")
            got = (await asyncio.wait_for(proc.stdout.readline(), 60)).decode().strip()
            assert got == "GOT Alice ping from another process", got
            sender, text = await asyncio.wait_for(replies.get(), 60)
            assert (sender, text) == ("Bob", "pong: ping from another process")
            assert (await asyncio.wait_for(proc.stdout.readline(), 60)).decode().strip() == "REPLIED True"
            assert await asyncio.wait_for(proc.wait(), 60) == 0
        finally:
            if proc.returncode is None:
                proc.kill()
            await alice.stop()
    asyncio.run(run())
