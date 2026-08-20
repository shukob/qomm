"""A user client that sends on a fixed schedule whether or not it has a request.

The schedule is the privacy mechanism: a client that only spoke when it had
something to say would announce its activity by the act of speaking. Here every
client sends exactly one constant-size frame to every relay in every slot, so the
transport carries the same traffic regardless of who is trading.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from .wire import Frame, frame_mac, share_request

N_REQUEST_VALUES = 4          # asset, quantity, direction, entity


@dataclass
class SendRecord:
    slot: int
    node: int
    sent_at: float
    size: int
    was_real: bool            # ground truth, recorded only so an attack can be scored


@dataclass
class Client:
    client_id: int
    key: bytes
    ports: list[int]
    sends: list[SendRecord] = field(default_factory=list)
    _writers: list[asyncio.StreamWriter] = field(default_factory=list)

    async def connect(self) -> None:
        for port in self.ports:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            self._writers.append(writer)

    async def send_slot(self, slot: int, request: list[int] | None) -> None:
        """One frame per node per slot. `None` means cover traffic."""
        real = request is not None
        values = request if real else [0] * N_REQUEST_VALUES
        payloads = share_request(values, len(self._writers))
        for node, (writer, payload) in enumerate(zip(self._writers, payloads)):
            frame = Frame(slot=slot, node=node, payload=payload,
                          mac=frame_mac(self.key, slot, node, payload))
            writer.write(frame.encode())
            self.sends.append(SendRecord(slot, node, time.perf_counter(),
                                         len(frame.encode()), real))
        await asyncio.gather(*(w.drain() for w in self._writers))

    async def close(self) -> None:
        for writer in self._writers:
            writer.close()
        for writer in self._writers:
            try:
                await writer.wait_closed()
            except (ConnectionError, asyncio.CancelledError):
                pass
