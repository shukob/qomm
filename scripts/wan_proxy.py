#!/usr/bin/env python3
"""Bidirectional loopback TCP proxies, one delay per link.

A single delay for every link models seven nodes at equal distance, which is the
one arrangement a real deployment will not have. Round time is set by the
slowest link a round waits on, not the average, so a per-link delay is the
difference between "the nodes are far apart" and "one node is far away" --- and
those should cost the same, which is a claim worth being able to test.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import time


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, delay: float) -> None:
    try:
        while data := await reader.read(65536):
            await asyncio.sleep(delay)
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass


async def handle(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    target_port: int,
    delay: float,
) -> None:
    deadline = time.monotonic() + 30.0
    while True:
        try:
            server_reader, server_writer = await asyncio.open_connection("127.0.0.1", target_port)
            break
        except ConnectionRefusedError:
            if time.monotonic() >= deadline:
                client_writer.close()
                await client_writer.wait_closed()
                return
            await asyncio.sleep(0.01)
    try:
        await asyncio.gather(
            pipe(client_reader, server_writer, delay),
            pipe(server_reader, client_writer, delay),
        )
    finally:
        for writer in (server_writer, client_writer):
            writer.close()
        for writer in (server_writer, client_writer):
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass


async def main_async(config_path: Path, ready_path: Path) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    default_delay = float(config["one_way_delay_ms"]) / 1000.0
    servers = []
    for proxy in config["proxies"]:
        server = await asyncio.start_server(
            lambda reader, writer, target=proxy["target_port"],
                   d=float(proxy.get("one_way_delay_ms", config["one_way_delay_ms"])) / 1000.0:
                handle(reader, writer, target, d),
            "127.0.0.1",
            proxy["listen_port"],
        )
        servers.append(server)
    ready_path.write_text(json.dumps({"status": "ready", "proxy_count": len(servers)}), encoding="utf-8")
    await asyncio.gather(*(server.serve_forever() for server in servers))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(main_async(args.config, args.ready))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
