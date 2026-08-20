#!/usr/bin/env python3
"""A resident quoting service, so a quote stops paying for a compiler.

Measuring where a quote's wall time goes turned up 258 ms of fixed cost per
invocation against 166 ms of actual protocol. Almost all of it is the MP-SPDZ
compiler, which runs every time even though the circuit for a given shape ---
maker count, mode, bit width --- never changes. Compiling once at start-up and
keeping the bytecode removes it.

The protocol is one JSON object per line, so a client needs no library:

    {"n_mm": 16, "mode": "rfq", "bit_length": 31, "user_qty": 100}
    -> {"ok": true, "quote": 99990, "winner": 5, "protocol_ms": 166.2, ...}

What this does *not* do is keep the seven party processes alive between quotes.
That is worth another 42 ms by the same measurement, and it needs the MP-SPDZ
client interface with its own certificates, so it is a separate change and is
not made here.
"""

from __future__ import annotations

import argparse
import json
import os
import socketserver
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qomm_dsl.registry import CircuitRegistry, program_digest  # noqa: E402
from scripts.run_qomm import MPSpdzRun, verify  # noqa: E402

QOMM_DIR = ROOT


SHAPE = ("n_mm", "n_parties", "mode", "rfs_steps", "disclose", "bit_length",
         "argmin_arity", "n_assets", "n_requests", "edabit", "audit_gates",
         "public_maker_assets", "threshold")

DEFAULTS = {"n_mm": 16, "n_parties": 7, "mode": "rfq", "rfs_steps": 5,
            "disclose": "none", "bit_length": 31, "argmin_arity": 2, "n_assets": 1,
            "n_requests": 1, "edabit": False, "audit_gates": False,
            "public_maker_assets": False, "threshold": 2, "user_qty": 100,
            "user_dir": 0, "user_asset": 0, "seed": 7, "is_real": 1,
            "delay_ms": 0.0}


def generate(request: dict, out_dir: Path, inputs_only: bool = False
             ) -> tuple[Path, Path, dict]:
    """Emit the circuit and the inputs for one request, or only the inputs."""
    out_dir.mkdir(parents=True, exist_ok=True)
    source = out_dir / "program.mpc"
    inputs = out_dir / "inputs"
    reference = out_dir / "reference.json"
    cmd = [sys.executable, str(QOMM_DIR / "mp_spdz" / "gen_qomm.py"),
           "--n-mm", str(request["n_mm"]), "--n-parties", str(request["n_parties"]),
           "--mode", request["mode"], "--rfs-steps", str(request["rfs_steps"]),
           "--disclose", request["disclose"], "--user-qty", str(request["user_qty"]),
           "--user-dir", str(request["user_dir"]), "--seed", str(request["seed"]),
           "--is-real", str(request["is_real"]), "--n-assets", str(request["n_assets"]),
           "--user-asset", str(request["user_asset"]),
           "--bit-length", str(request["bit_length"]),
           "--argmin-arity", str(request["argmin_arity"]),
           "--n-requests", str(request["n_requests"]),
           "--out-program", str(source), "--out-input-dir", str(inputs),
           "--out-reference", str(reference)]
    if inputs_only:
        cmd.append("--inputs-only")
    if request["edabit"]:
        cmd.append("--edabit")
    if request["public_maker_assets"]:
        cmd.append("--public-maker-assets")
    if request["audit_gates"]:
        cmd.append("--audit-gates")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"circuit generation failed: {proc.stderr[-800:]}")
    return source, inputs, json.loads(reference.read_text())


class Shape:
    """One compiled circuit, kept for as long as the service runs."""

    def __init__(self, run: MPSpdzRun, source: Path, compile_ms: float):
        self.run = run
        self.source = source
        self.compile_ms = compile_ms
        self.served = 0


class CircuitCache:
    """One compiled circuit per shape, compiled on first use.

    Keyed by everything the generator turns into bytecode. Anything that only
    changes the inputs --- quantities, directions, the requested market --- is
    deliberately not part of the key, because those must not force a recompile
    and, more to the point, must not be visible in what gets compiled.
    """

    def __init__(self, root: Path, workdir: Path,
                 registry: CircuitRegistry | None = None):
        self.root = root
        self.workdir = workdir
        self.shapes: dict[tuple, Shape] = {}
        # When set, no shape reaches the compiler until its emitted program
        # matches what was approved for it. Checking afterwards would mean the
        # answers are already out, which is the wrong end of the exchange to
        # discover a substituted circuit.
        self.registry = registry

    @staticmethod
    def normalise(request: dict) -> dict:
        filled = dict(DEFAULTS)
        filled.update(request)
        return filled

    @staticmethod
    def key(request: dict) -> tuple:
        return tuple((name, request[name]) for name in SHAPE)

    def get(self, request: dict) -> Shape:
        key = self.key(request)
        if key in self.shapes:
            return self.shapes[key]
        index = len(self.shapes)
        out_dir = self.workdir / f"shape{index}"
        source, inputs, _ = generate(request, out_dir)
        if self.registry is not None:
            ok, reason = self.registry.check(source.read_text(), key)
            if not ok:
                raise RuntimeError(f"refusing to compile this circuit: {reason}")
        program = f"qomm_serve_{os.getpid()}_{index}"
        run = MPSpdzRun(self.root, program, request["n_parties"], request["threshold"])
        run.install(source, inputs)
        t = time.perf_counter()
        run.compile()
        shape = Shape(run, source, (time.perf_counter() - t) * 1e3)
        self.shapes[key] = shape
        return shape

    def quote(self, request: dict) -> dict:
        """Compile once; afterwards a quote only writes inputs and runs."""
        request = self.normalise(request)
        shape = self.get(request)
        out_dir = self.workdir / "live"
        _, inputs, reference = generate(request, out_dir, inputs_only=True)
        # reinstall the inputs against the already-compiled program
        shape.run.install(shape.source, inputs)
        result = shape.run.execute(request["delay_ms"])
        if not result["ok"]:
            raise RuntimeError("a party failed")
        ok, detail = verify(request["mode"], result["log"], reference)
        shape.served += 1
        return {"verified": ok, "detail": detail,
                "protocol_ms": (result["party0_seconds"] or 0.0) * 1e3,
                "wall_ms": result["wall_seconds"] * 1e3,
                "rounds": result["party0_rounds"], "mb": result["party0_mb"],
                "compiled_once_ms": shape.compile_ms, "served_by_shape": shape.served}


def _entry_from(entry: dict):
    """Rebuild one approved circuit from its stored digests."""
    from qomm_dsl.registry import ApprovedCircuit

    return ApprovedCircuit(name=entry["name"], rule_digest=entry.get("rule_digest", ""),
                           program_digest=entry["program_digest"],
                           shape=tuple(entry["shape"]))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--mp-spdz-root", default=os.environ.get(
        "MP_SPDZ_ROOT", str(Path.home() / "work/qomm/MP-SPDZ")))
    ap.add_argument("--warm", type=json.loads, default=None,
                    help="a shape to compile at start-up rather than on first use")
    ap.add_argument("--approved", type=Path, default=None,
                    help="a JSON file of approved circuits; without it any shape "
                         "compiles, which is the right default for measurement "
                         "and the wrong one for a deployment")
    ap.add_argument("--approve-into", type=Path, default=None,
                    help="write the digests of the shapes this run compiles, to "
                         "bootstrap that file from a circuit already trusted")
    args = ap.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="qomm-serve-"))
    registry = None
    if args.approved:
        registry = CircuitRegistry()
        for entry in json.loads(args.approved.read_text()):
            registry._approved[tuple(entry["shape"])] = _entry_from(entry)
        print(f"{len(registry.approved_shapes())} approved shape(s) loaded", flush=True)
    cache = CircuitCache(Path(args.mp_spdz_root), workdir, registry=registry)
    if args.warm:
        shape = cache.get(cache.normalise(args.warm))
        print(f"warmed one shape in {shape.compile_ms:.1f} ms", flush=True)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            for line in self.rfile:
                line = line.strip()
                if not line:
                    continue
                try:
                    request = json.loads(line)
                    t = time.perf_counter()
                    result = cache.quote(request)
                    reply = {"ok": True,
                             "service_ms": (time.perf_counter() - t) * 1e3, **result}
                except Exception as exc:                       # noqa: BLE001
                    reply = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                self.wfile.write((json.dumps(reply) + "\n").encode())
                self.wfile.flush()

    if args.approve_into:
        approved = [{"name": f"shape{i}", "program_digest": program_digest(
            shape.source.read_text()), "shape": list(key)}
            for i, (key, shape) in enumerate(cache.shapes.items())]
        args.approve_into.write_text(json.dumps(approved, indent=2) + "\n")
        print(f"wrote {len(approved)} approved shape(s) to {args.approve_into}", flush=True)

    with socketserver.ThreadingTCPServer((args.host, args.port), Handler) as server:
        server.allow_reuse_address = True
        print(f"serving on {args.host}:{args.port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
