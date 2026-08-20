#!/usr/bin/env python3
"""Median TCP connect time to a host:port, in milliseconds.

Used to record the real propagation delay of a two-site run. ICMP is filtered on
the remote site, so a TCP handshake is the available measurement.
"""

from __future__ import annotations

import socket
import statistics
import sys


def main() -> int:
    host, port = sys.argv[1], int(sys.argv[2])
    attempts = int(sys.argv[3]) if len(sys.argv) > 3 else 9
    samples = []
    for _ in range(attempts):
        sock = socket.socket()
        sock.settimeout(5)
        start = __import__("time").perf_counter()
        try:
            sock.connect((host, port))
            samples.append((__import__("time").perf_counter() - start) * 1000)
        except OSError:
            pass
        finally:
            sock.close()
    print(f"{statistics.median(samples):.2f}" if samples else "nan")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
