"""HTTP and WebSocket on the standard library, because a demo must not need pip.

The demo is meant to be opened on a laptop in a meeting room, on a phone over
the venue's wireless, on whatever machine is nearest. Anything that starts with
"first install" is a demo that does not get given. So the page, its assets and
the socket all come out of one asyncio server with nothing imported that is not
already in the interpreter.

The WebSocket half is RFC 6455 reduced to what this needs: the handshake, text
frames, continuation, ping, pong and close. No permessage-deflate --- a JSON
view of one seat is a couple of kilobytes and compressing it would buy less than
the code would cost. Frames from a browser are always masked and frames from a
server never are, and both directions are enforced rather than assumed, because
a stray unmasked client frame means something other than a browser is talking.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import struct
from dataclasses import dataclass, field

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

CONT, TEXT, BINARY, CLOSE, PING, PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA

# A view of one seat is a few kilobytes. Anything far larger arriving from a
# browser is a mistake or an attempt, and either way is not worth buffering.
MAX_FRAME = 1 << 20


class ProtocolError(Exception):
    pass


@dataclass
class Connection:
    """One browser. Everything the room knows it by hangs off this."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    session: str = ""
    peer: str = ""
    query: dict = field(default_factory=dict)
    open: bool = True

    async def send(self, payload: dict) -> None:
        if not self.open:
            return
        try:
            self.writer.write(frame(TEXT, json.dumps(payload).encode()))
            await self.writer.drain()
        except (ConnectionError, RuntimeError):
            self.open = False

    async def close(self) -> None:
        self.open = False
        try:
            self.writer.write(frame(CLOSE, b""))
            await self.writer.drain()
        except (ConnectionError, RuntimeError):
            pass
        self.writer.close()


def frame(opcode: int, payload: bytes) -> bytes:
    """One unmasked server frame. Servers never mask; browsers always do."""
    head = bytes([0x80 | opcode])
    size = len(payload)
    if size < 126:
        head += bytes([size])
    elif size < (1 << 16):
        head += bytes([126]) + struct.pack("!H", size)
    else:
        head += bytes([127]) + struct.pack("!Q", size)
    return head + payload


async def read_frame(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    """One complete message, continuation frames joined."""
    opcode_of_message = None
    body = bytearray()
    while True:
        header = await reader.readexactly(2)
        final = bool(header[0] & 0x80)
        opcode = header[0] & 0x0F
        masked = bool(header[1] & 0x80)
        size = header[1] & 0x7F
        if size == 126:
            size = struct.unpack("!H", await reader.readexactly(2))[0]
        elif size == 127:
            size = struct.unpack("!Q", await reader.readexactly(8))[0]
        if size > MAX_FRAME:
            raise ProtocolError(f"frame of {size} bytes refused")
        if not masked:
            raise ProtocolError("a client frame must be masked")
        key = await reader.readexactly(4)
        chunk = bytearray(await reader.readexactly(size))
        for i in range(size):
            chunk[i] ^= key[i & 3]
        if opcode in (PING, PONG, CLOSE):        # control frames never fragment
            return opcode, bytes(chunk)
        if opcode_of_message is None:
            opcode_of_message = opcode
        body += chunk
        if final:
            return opcode_of_message, bytes(body)


def handshake(headers: dict[str, str]) -> bytes | None:
    key = headers.get("sec-websocket-key")
    if not key or headers.get("upgrade", "").lower() != "websocket":
        return None
    accept = base64.b64encode(
        hashlib.sha1(key.encode() + GUID).digest()).decode()
    return ("HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode()


TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
         ".js": "application/javascript; charset=utf-8",
         ".svg": "image/svg+xml", ".ico": "image/x-icon",
         ".json": "application/json; charset=utf-8"}


def http_reply(status: str, body: bytes, kind: str) -> bytes:
    return (f"HTTP/1.1 {status}\r\n"
            f"Content-Type: {kind}\r\n"
            f"Content-Length: {len(body)}\r\n"
            # The page holds a seat; a cached copy of an older one would claim
            # a seat with stale code and be very hard to explain in a room.
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n\r\n").encode() + body


class Server:
    """Serves the page and the sockets. The room is handed in, not built here."""

    def __init__(self, static_dir, on_open, on_message, on_close):
        self.static = static_dir
        self.on_open = on_open
        self.on_message = on_message
        self.on_close = on_close

    async def handle(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
        connection = None
        try:
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
            lines = request.decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split(" ", 2)
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    name, value = line.split(":", 1)
                    headers[name.strip().lower()] = value.strip()
            path, _, raw_query = target.partition("?")
            if method != "GET":
                writer.write(http_reply("405 Method Not Allowed", b"", "text/plain"))
                await writer.drain()
                return
            if path == "/ws":
                reply = handshake(headers)
                if reply is None:
                    writer.write(http_reply("400 Bad Request", b"not a websocket",
                                            "text/plain"))
                    await writer.drain()
                    return
                writer.write(reply)
                await writer.drain()
                connection = Connection(reader, writer, query=parse_query(raw_query),
                                        peer=peer_of(writer))
                await self.on_open(connection)
                await self._pump(connection)
                return
            await self._serve_file(path, writer)
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError,
                ValueError, ProtocolError):
            pass
        finally:
            if connection is not None:
                connection.open = False
                await self.on_close(connection)
            try:
                writer.close()
            except (ConnectionError, RuntimeError):
                pass

    async def _pump(self, connection: Connection) -> None:
        while connection.open:
            opcode, payload = await read_frame(connection.reader)
            if opcode == CLOSE:
                break
            if opcode == PING:
                connection.writer.write(frame(PONG, payload))
                await connection.writer.drain()
                continue
            if opcode != TEXT:
                continue
            try:
                message = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(message, dict):
                await self.on_message(connection, message)

    async def _serve_file(self, path: str, writer: asyncio.StreamWriter) -> None:
        name = "index.html" if path in ("/", "") else path.lstrip("/")
        target = (self.static / name).resolve()
        # A path that climbs out of the static directory is refused rather than
        # normalised, because normalising it quietly is how these go wrong.
        if not str(target).startswith(str(self.static.resolve())) \
                or not target.is_file():
            writer.write(http_reply("404 Not Found", b"no such page", "text/plain"))
            await writer.drain()
            return
        kind = TYPES.get(target.suffix, "application/octet-stream")
        writer.write(http_reply("200 OK", target.read_bytes(), kind))
        await writer.drain()


def parse_query(raw: str) -> dict:
    out = {}
    for part in raw.split("&"):
        if not part:
            continue
        name, _, value = part.partition("=")
        out[unquote(name)] = unquote(value)
    return out


def unquote(text: str) -> str:
    out = bytearray()
    i = 0
    raw = text.replace("+", " ").encode("latin-1", "ignore")
    while i < len(raw):
        if raw[i] == 0x25 and i + 2 < len(raw):
            try:
                out.append(int(raw[i + 1:i + 3], 16))
                i += 3
                continue
            except ValueError:
                pass
        out.append(raw[i])
        i += 1
    return out.decode("utf-8", "replace")


def peer_of(writer: asyncio.StreamWriter) -> str:
    try:
        host, port, *_ = writer.get_extra_info("peername")
        return f"{host}:{port}"
    except (TypeError, ValueError):
        return "?"


def lan_addresses(port: int) -> list[str]:
    """Every address a second machine could reach this server on.

    Printed at start-up because the first question in a room with more than one
    laptop in it is always "what do I type", and the answer is not `localhost`.
    """
    import socket

    found = {f"http://127.0.0.1:{port}/"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            address = info[4][0]
            if ":" in address or address.startswith("127."):
                continue
            found.add(f"http://{address}:{port}/")
    except OSError:
        pass
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("192.0.2.1", 1))       # a reserved address; nothing is sent
        found.add(f"http://{probe.getsockname()[0]}:{port}/")
        probe.close()
    except OSError:
        pass
    return sorted(found, key=lambda url: ("127.0.0.1" in url, url))


def env_flag(name: str) -> bool:
    return os.environ.get(name, "").lower() in ("1", "true", "yes", "on")
