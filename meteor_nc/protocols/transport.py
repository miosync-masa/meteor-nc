"""
Plain asyncio TCP transport for Meteor-NC v3 envelopes, plus signed
address records for routing.

The transport carries bytes only. Confidentiality, sender authentication,
integrity and replay protection all live in the envelope
(protocols/envelope.py), so the transport needs no crypto of its own:
an attacker on the path can drop or delay messages, nothing more.

Frame (one envelope per connection):
    "MNCT" | u32 length | envelope bytes      ->   1-byte ack (1 accepted, 0 rejected)

Address record: who can be reached where, signed by the owner:
    "MNCA" | version | MeteorID | lp(bundle) | lp(json addrs) | u64 time_ms | lp(signature)
The signature is the owner's hybrid (Ed25519 + ML-DSA-65) signature, and
the bundle must hash to the MeteorID, so a record cannot point someone
else's MeteorID at an attacker's address.
"""

from __future__ import annotations

import asyncio
import json
import logging
import struct
import time
from typing import Awaitable, Callable, List, Optional, Tuple

from .envelope import (
    EnvelopeError,
    MeteorIdentity,
    check_peer,
    parse_bundle,
    verify_signature,
)

logger = logging.getLogger("meteor-transport")

FRAME_MAGIC = b"MNCT"
RECORD_MAGIC = b"MNCA"
RECORD_VERSION = 1
MAX_FRAME = 64 << 20
IO_TIMEOUT_S = 15.0


def _lp(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


# ---------------------------------------------------------------------------
# address records
# ---------------------------------------------------------------------------

def make_address_record(identity: MeteorIdentity, addrs: List[str]) -> bytes:
    body = (RECORD_MAGIC + bytes([RECORD_VERSION]) + identity.meteor_id + _lp(identity.bundle)
            + _lp(json.dumps(list(addrs)).encode()) + struct.pack(">Q", int(time.time() * 1000)))
    return body + _lp(identity.sign(b"meteor-nc-v3-addr" + body))


def parse_address_record(record: bytes, max_age_s: Optional[float] = None
                         ) -> Tuple[bytes, bytes, List[str], float]:
    """Verify a record; return (meteor_id, bundle, addrs, timestamp_s)."""
    try:
        if record[:4] != RECORD_MAGIC or record[4] != RECORD_VERSION:
            raise EnvelopeError("not an address record")
        o = 5
        meteor_id = record[o:o + 32]; o += 32

        def lp():
            nonlocal o
            (n,) = struct.unpack(">I", record[o:o + 4])
            v = record[o + 4:o + 4 + n]
            if len(v) != n:
                raise EnvelopeError("truncated address record")
            o += 4 + n
            return v

        bundle = lp()
        addrs = json.loads(lp().decode())
        (ts,) = struct.unpack(">Q", record[o:o + 8]); o += 8
        body_end = o
        sig = lp()
    except EnvelopeError:
        raise
    except Exception:
        raise EnvelopeError("malformed address record") from None
    if o != len(record) or not isinstance(addrs, list) or not all(isinstance(a, str) for a in addrs):
        raise EnvelopeError("malformed address record")
    check_peer(meteor_id, bundle)
    _, keys = parse_bundle(bundle)
    if not verify_signature(keys, sig, b"meteor-nc-v3-addr" + record[:body_end]):
        raise EnvelopeError("bad address record signature")
    if max_age_s is not None and time.time() - ts / 1000.0 > max_age_s:
        raise EnvelopeError("address record too old")
    return meteor_id, bundle, addrs, ts / 1000.0


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------

def _parse_addr(addr: str) -> Tuple[str, int]:
    if not addr.startswith("tcp://"):
        raise ValueError(f"not a tcp address: {addr}")
    host, _, port = addr[len("tcp://"):].rpartition(":")
    return host.strip("[]"), int(port)


class TCPTransport:
    """One envelope per TCP connection, acknowledged with one byte."""

    def __init__(self, handler: Callable[[bytes], Awaitable[bool]], max_frame: int = MAX_FRAME):
        self._handler = handler
        self.max_frame = int(max_frame)
        self._server: Optional[asyncio.base_events.Server] = None
        self.addrs: List[str] = []

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> str:
        self._server = await asyncio.start_server(self._serve, host, port)
        sock = self._server.sockets[0].getsockname()
        h = f"[{sock[0]}]" if ":" in sock[0] else sock[0]
        self.addrs = [f"tcp://{h}:{sock[1]}"]
        return self.addrs[0]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ok = False
        try:
            head = await asyncio.wait_for(reader.readexactly(8), IO_TIMEOUT_S)
            if head[:4] != FRAME_MAGIC:
                raise ValueError("bad frame magic")
            (n,) = struct.unpack(">I", head[4:])
            if n > self.max_frame:
                raise ValueError("frame too large")
            data = await asyncio.wait_for(reader.readexactly(n), IO_TIMEOUT_S)
            ok = bool(await self._handler(data))
        except Exception as e:  # noqa: BLE001 - every failure is a rejection
            logger.debug("rejected connection: %s", e)
        try:
            writer.write(b"\x01" if ok else b"\x00")
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass
        finally:
            writer.close()

    @staticmethod
    async def send(addr: str, data: bytes, timeout: float = IO_TIMEOUT_S) -> bool:
        """Deliver one envelope; True only if the receiver accepted it."""
        try:
            host, port = _parse_addr(addr)
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        except Exception as e:  # noqa: BLE001
            logger.warning("connect to %s failed: %s", addr, e)
            return False
        try:
            writer.write(FRAME_MAGIC + struct.pack(">I", len(data)) + data)
            await writer.drain()
            ack = await asyncio.wait_for(reader.readexactly(1), timeout)
            return ack == b"\x01"
        except Exception as e:  # noqa: BLE001
            logger.warning("send to %s failed: %s", addr, e)
            return False
        finally:
            writer.close()


__all__ = ["TCPTransport", "make_address_record", "parse_address_record", "MAX_FRAME"]
