"""
Separate-process peer for tests/test_transport.py.

    python tests/peer_process.py <alice_address_record_hex>

Starts a MeteorWeb4Node ("Bob") on TCP, adds Alice from her signed record,
prints "RECORD <hex>" (Bob's own signed record), waits for one message,
prints "GOT <sender> <text>", replies "pong: <text>" to Alice over TCP,
prints "REPLIED <ok>", and exits.
"""
import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
logging.disable(logging.WARNING)

from meteor_nc.protocols.web4 import MeteorWeb4Node  # noqa: E402


async def main(alice_record_hex: str) -> None:
    bob = MeteorWeb4Node("Bob", local_delivery=False)
    await bob.start_tcp("127.0.0.1", 0)
    bob.add_peer_from_record("Alice", bytes.fromhex(alice_record_hex))
    got: asyncio.Queue = asyncio.Queue()

    async def handler(sender, data, env):
        await got.put((sender, data.decode()))
    bob.on_message(handler)
    print("RECORD", bob.get_address_record().hex(), flush=True)
    sender, text = await asyncio.wait_for(got.get(), 60)
    print("GOT", sender, text, flush=True)
    ok = await bob.send_text("Alice", f"pong: {text}")
    print("REPLIED", ok, flush=True)
    await bob.stop()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
