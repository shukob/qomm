#!/usr/bin/env python3
"""What keeping the compiler out of the quote path is worth.

Measuring one quote turned up 258 ms of fixed cost against 166 ms of protocol,
and almost all of the fixed cost was MP-SPDZ compiling a circuit whose shape had
not changed. `scripts/serve_qomm.py` compiles once per shape and keeps the
bytecode. This measures what that buys, and it measures the thing it is being
compared against in the same run on the same machine --- the earlier numbers for
the two paths came from separate sessions, which is exactly the mistake this
project already had to publish a correction for.

Both arms go through the same `CircuitCache.quote`. The cold arm just throws the
cache away after every quote, so the only difference between the two is whether
the compiler runs, not which code path runs.
"""

from __future__ import annotations

import argparse
import json
import platform
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.serve_qomm import CircuitCache                                  # noqa: E402

from scripts.hosts import this_host                                          # noqa: E402


def calibration(repeats: int = 200) -> dict:
    """The same yardstick the other artifacts carry, plus a compile.

    The scalar multiplication catches a machine that is not in the state it was
    in last time. It has nothing to do with MPC, which is the point: it is
    comparable against every other artifact here, including the Rust one.
    """
    from zk.groups import make_group

    group = make_group("ed25519")
    point = group.hash_to_point(b"calibration")
    samples = []
    for _ in range(repeats):
        t = time.perf_counter()
        group.point_pow(point, 12345)
        samples.append((time.perf_counter() - t) * 1e6)
    return {"scalar_mult_us": statistics.median(samples)}


def request_for(batch: int, args) -> dict:
    return {"n_mm": args.n_mm, "n_parties": args.n_parties,
            "threshold": args.threshold, "mode": args.mode,
            "bit_length": args.bit_length, "n_requests": batch,
            "delay_ms": args.delay_ms}


def summarise(batch: int, samples: list[dict], compile_ms: float) -> dict:
    """Per-quote figures. Everything is divided by the batch, nothing else."""
    wall = statistics.median(s["wall_ms"] for s in samples)
    protocol = statistics.median(s["protocol_ms"] for s in samples)
    rounds = statistics.median(s["rounds"] for s in samples)
    return {"batch": batch,
            "quotes": len(samples) * batch,
            "wall_ms": wall,
            "ms_per_quote": wall / batch,
            "protocol_ms_per_quote": protocol / batch,
            "overhead_ms_per_quote": (wall - protocol) / batch,
            "rounds_per_quote": rounds / batch,
            "mb_per_quote": statistics.median(s["mb"] for s in samples) / batch,
            "compile_ms": compile_ms,
            "verified": all(s["verified"] for s in samples)}


def cold_arm(root: Path, batches: list[int], repeats: int, args) -> list[dict]:
    """No residency: a fresh cache per quote, so the compiler runs every time."""
    rows = []
    for batch in batches:
        samples, compiles = [], []
        for _ in range(repeats):
            workdir = Path(tempfile.mkdtemp(prefix="qomm-cold-"))
            cache = CircuitCache(root, workdir)
            t = time.perf_counter()
            result = cache.quote(request_for(batch, args))
            result["wall_ms"] = (time.perf_counter() - t) * 1e3
            samples.append(result)
            compiles.append(result["compiled_once_ms"])
        rows.append(summarise(batch, samples, statistics.median(compiles)))
        print(f"  cold     batch {batch:3}  {rows[-1]['ms_per_quote']:8.1f} ms/quote",
              flush=True)
    return rows


def resident_arm(root: Path, batches: list[int], repeats: int, args) -> list[dict]:
    """One cache for the whole run, warmed before the clock starts."""
    workdir = Path(tempfile.mkdtemp(prefix="qomm-resident-"))
    cache = CircuitCache(root, workdir)
    rows = []
    for batch in batches:
        request = request_for(batch, args)
        cache.quote(request)                      # warm this shape, not measured
        compile_ms = cache.get(cache.normalise(request)).compile_ms
        samples = []
        for _ in range(repeats):
            t = time.perf_counter()
            result = cache.quote(request)
            result["wall_ms"] = (time.perf_counter() - t) * 1e3
            samples.append(result)
        rows.append(summarise(batch, samples, compile_ms))
        print(f"  resident batch {batch:3}  {rows[-1]['ms_per_quote']:8.1f} ms/quote",
              flush=True)
    return rows


def transport_arm(root: Path, args, repeats: int = 3) -> dict:
    """What the socket costs, so the in-process numbers can stand for the service.

    Both arms above call `CircuitCache.quote` directly. The deployed service puts
    a line-delimited JSON socket in front of it, and a reader is entitled to ask
    whether that is where the saving went.
    """
    port = 8899
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "scripts" / "serve_qomm.py"),
         "--port", str(port), "--mp-spdz-root", str(root),
         "--warm", json.dumps(request_for(1, args))],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.time() + 300
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                raise RuntimeError("the service exited before it was ready")
            print(f"    [service] {line.strip()}", flush=True)
            if line.startswith("serving on"):
                break
        else:
            raise RuntimeError("the service did not come up")

        samples = []
        with socket.create_connection(("127.0.0.1", port), timeout=600) as sock:
            f = sock.makefile("rwb")
            for _ in range(repeats):
                t = time.perf_counter()
                f.write((json.dumps(request_for(1, args)) + "\n").encode())
                f.flush()
                reply = json.loads(f.readline())
                client_ms = (time.perf_counter() - t) * 1e3
                if not reply.get("ok"):
                    raise RuntimeError(reply.get("error", "the service refused"))
                samples.append({"client_ms": client_ms,
                                "service_ms": reply["service_ms"]})
        client = statistics.median(s["client_ms"] for s in samples)
        service = statistics.median(s["service_ms"] for s in samples)
        return {"client_ms": client, "service_ms": service,
                "socket_ms": client - service, "repeats": repeats}
    finally:
        proc.terminate()
        proc.wait(timeout=30)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mp-spdz-root", type=Path,
                    default=Path.home() / "work/qomm/MP-SPDZ")
    ap.add_argument("--batches", type=int, nargs="+", default=[1, 4, 16, 32])
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--n-mm", type=int, default=16)
    ap.add_argument("--n-parties", type=int, default=7)
    ap.add_argument("--threshold", type=int, default=2)
    ap.add_argument("--mode", default="rfq")
    ap.add_argument("--bit-length", type=int, default=31)
    ap.add_argument("--delay-ms", type=float, default=0.0)
    ap.add_argument("--skip-transport", action="store_true")
    ap.add_argument("--out", type=Path, default=ROOT / "artifacts" / "mpc_resident.json")
    args = ap.parse_args()

    result = {"host": this_host(), "python": platform.python_version(),
              "protocol": "malicious-shamir-party.x",
              "n_parties": args.n_parties, "threshold": args.threshold,
              "n_mm": args.n_mm, "mode": args.mode, "bit_length": args.bit_length,
              "repeats": args.repeats}
    result["calibration"] = calibration()
    print(f"calibration: scalar mult {result['calibration']['scalar_mult_us']:.1f} us",
          flush=True)

    result["cold"] = cold_arm(args.mp_spdz_root, args.batches, args.repeats, args)
    result["resident"] = resident_arm(args.mp_spdz_root, args.batches, args.repeats, args)
    if not args.skip_transport:
        result["transport"] = transport_arm(args.mp_spdz_root, args)
        print(f"  socket adds {result['transport']['socket_ms']:.2f} ms", flush=True)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
