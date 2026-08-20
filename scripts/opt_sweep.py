#!/usr/bin/env python3
"""Measure the MPC optimisation axes against the shipped baseline.

Axes, each of which is expected to move a different term of

    T(M, delta) = T_offline + R(M) * 2*delta + W(M)/B + C(M)

  bit_length     comparison width  -> W and, if comparisons are not constant
                                      round, also R
  argmin_arity   tournament depth  -> R at the cost of W
  edabit         where comparison bits come from -> R at the cost of preprocessing
  protocol       malicious vs semi-honest -> everything, and is the price of the
                 threat model rather than an optimisation

Every configuration is verified against the cleartext reference before its
timing is recorded.
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run_one(root: Path, **kw) -> dict:
    cmd = [sys.executable, str(HERE / "run_qomm.py"), "--mp-spdz-root", str(root)]
    flags = kw.pop("flags", [])
    for key, value in kw.items():
        if value is None:
            continue
        cmd += [f"--{key.replace('_', '-')}", str(value)]
    cmd += flags
    proc = subprocess.run(cmd, capture_output=True, text=True)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        payload = {"error": "unparseable", "stderr": proc.stderr[-1500:], **kw}
    payload.get("circuit", {}).pop("compile_log", None)
    return payload


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mp-spdz-root", type=Path,
                    default=Path(os.environ.get("MP_SPDZ_ROOT", "")))
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--mode", default="rfq")
    ap.add_argument("--mms", type=int, nargs="+", default=[16, 64])
    ap.add_argument("--delays", type=float, nargs="+", default=[0, 5, 15])
    ap.add_argument("--bit-lengths", type=int, nargs="+", default=[63, 31])
    ap.add_argument("--arities", type=int, nargs="+", default=[2, 4, 8])
    ap.add_argument("--edabits", nargs="+", default=["off", "on"])
    ap.add_argument("--protocols", nargs="+", default=["malicious-shamir-party.x"])
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--n-parties", type=int, default=7)
    ap.add_argument("--threshold", type=int, default=2)
    args = ap.parse_args()

    jobs = []
    for n_mm, delay, bits, arity, eda, proto in itertools.product(
            args.mms, args.delays, args.bit_lengths, args.arities, args.edabits, args.protocols):
        if arity > n_mm:
            continue
        jobs.append(dict(n_mm=n_mm, delay_ms=delay, bit_length=bits,
                         argmin_arity=arity, edabit=eda, protocol=proto))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    total = len(jobs)
    with args.out.open("a", encoding="utf-8") as handle:
        for index, job in enumerate(jobs, 1):
            eda = job.pop("edabit")
            started = time.time()
            payload = run_one(
                args.mp_spdz_root, mode=args.mode, repeats=args.repeats,
                n_parties=args.n_parties, threshold=args.threshold,
                tag=f"opt-{index}", flags=(["--edabit"] if eda == "on" else []), **job)
            payload["edabit"] = eda == "on"
            payload["sweep_seconds"] = time.time() - started
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
            handle.flush()
            print(f"[{index}/{total}] M={job['n_mm']} d={job['delay_ms']}ms "
                  f"bits={job['bit_length']} arity={job['argmin_arity']} eda={eda} "
                  f"{job['protocol'].replace('-party.x','')} -> "
                  f"rounds={payload.get('measured_rounds')} "
                  f"mb={payload.get('measured_mb')} "
                  f"median={payload.get('wall_median')} "
                  f"ok={payload.get('verified')}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
