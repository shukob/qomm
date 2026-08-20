#!/usr/bin/env python3
"""Run the pre-registered QOMM measurement sweep and append results to JSONL.

Sweep axes are fixed in THEORY.md section 3:
  M in {4,8,16,32,64}, one-way delay in {0,1,5,15} ms,
  mode in {rfq, rfm, rfs}, disclosure in {none, threshold}.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run_one(root: Path, out_dir: Path, **kw) -> dict:
    cmd = [sys.executable, str(HERE / "run_qomm.py"), "--mp-spdz-root", str(root)]
    for key, value in kw.items():
        if value is None:
            continue
        cmd += [f"--{key.replace('_', '-')}", str(value)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        payload = {"error": "unparseable", "stdout": proc.stdout[-2000:], "stderr": proc.stderr[-2000:], **kw}
    payload.setdefault("circuit", {}).pop("compile_log", None)
    payload["returncode"] = proc.returncode
    return payload


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mp-spdz-root", type=Path,
                    default=Path(os.environ.get("MP_SPDZ_ROOT", "")))
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--mms", type=int, nargs="+", default=[4, 8, 16, 32, 64])
    ap.add_argument("--delays", type=float, nargs="+", default=[0, 1, 5, 15])
    ap.add_argument("--modes", nargs="+", default=["rfq", "rfm", "rfs"])
    ap.add_argument("--rfs-steps", type=int, default=5)
    ap.add_argument("--n-parties", type=int, default=7)
    ap.add_argument("--threshold", type=int, default=2)
    ap.add_argument("--with-threshold-disclosure", action="store_true")
    args = ap.parse_args()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    jobs = []
    for mode in args.modes:
        for n_mm in args.mms:
            for delay in args.delays:
                jobs.append(dict(mode=mode, n_mm=n_mm, delay_ms=delay, disclose="none"))
                if args.with_threshold_disclosure and mode == "rfq":
                    jobs.append(dict(mode=mode, n_mm=n_mm, delay_ms=delay, disclose="threshold"))

    total = len(jobs)
    with args.out.open("a", encoding="utf-8") as handle:
        for index, job in enumerate(jobs, 1):
            started = time.time()
            payload = run_one(
                args.mp_spdz_root, args.out.parent,
                repeats=args.repeats, n_parties=args.n_parties,
                threshold=args.threshold, rfs_steps=args.rfs_steps,
                tag=f"sweep-{index}", **job,
            )
            payload["sweep_index"] = index
            payload["sweep_seconds"] = time.time() - started
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
            handle.flush()
            summary = (
                f"[{index}/{total}] {job['mode']} M={job['n_mm']} d={job['delay_ms']}ms "
                f"{job['disclose']} -> rounds={payload.get('measured_rounds')} "
                f"median={payload.get('wall_median')} verified={payload.get('verified')}"
            )
            print(summary, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
