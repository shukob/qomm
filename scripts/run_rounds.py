#!/usr/bin/env python3
"""Where the communication rounds go, and what actually removes them.

The decomposition matters more than any single number: rounds are set by the
sequential depth of the comparison chain, so anything that only narrows a layer
buys bandwidth, not latency. Batching is the exception, because rounds are a
property of the job rather than of the request.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(root: Path, flags: list[str] | None = None, **kw) -> dict:
    cmd = [sys.executable, str(HERE / "run_qomm.py"), "--mp-spdz-root", str(root)]
    for key, value in kw.items():
        cmd += [f"--{key.replace('_', '-')}", str(value)]
    cmd += flags or []
    proc = subprocess.run(cmd, capture_output=True, text=True)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"error": "unparseable", "stderr": proc.stderr[-600:]}
    payload.get("circuit", {}).pop("compile_log", None)
    return payload


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mp-spdz-root", type=Path,
                    default=Path(os.environ.get("MP_SPDZ_ROOT", "")))
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--n-mm", type=int, default=16)
    ap.add_argument("--n-assets", type=int, default=4)
    ap.add_argument("--bit-length", type=int, default=31)
    ap.add_argument("--delay-ms", type=float, default=15.0)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--batches", type=int, nargs="+", default=[10000, 1000, 100])
    ap.add_argument("--requests", type=int, nargs="+", default=[1, 2, 4, 8, 16, 32])
    args = ap.parse_args()

    common = dict(n_mm=args.n_mm, n_assets=args.n_assets, bit_length=args.bit_length,
                  delay_ms=args.delay_ms, repeats=args.repeats)
    payload: dict = {"config": {k: (str(v) if isinstance(v, Path) else v)
                                for k, v in vars(args).items()}}

    print("== preprocessing batch size ==", flush=True)
    payload["batch"] = []
    for batch in args.batches:
        row = run(args.mp_spdz_root, batch_size=batch, **common)
        payload["batch"].append(row)
        print(f"  batch={batch:6d}  rounds={row.get('measured_rounds')}  "
              f"mb={row.get('measured_mb')}  median={row.get('wall_median')}", flush=True)

    print("== trimming work out of the gate layer ==", flush=True)
    payload["gates"] = []
    for label, flags in (("baseline", []),
                         ("public maker assets", ["--public-maker-assets"]),
                         ("gates moved to the audit", ["--audit-gates"]),
                         ("both", ["--public-maker-assets", "--audit-gates"])):
        row = run(args.mp_spdz_root, flags=flags, **common)
        row["label"] = label
        payload["gates"].append(row)
        print(f"  {label:26s} rounds={row.get('measured_rounds')}  "
              f"mb={row.get('measured_mb')}  median={row.get('wall_median')}", flush=True)

    print("== batching requests into one job ==", flush=True)
    payload["batching"] = []
    for requests in args.requests:
        row = run(args.mp_spdz_root, n_requests=requests,
                  flags=["--public-maker-assets", "--audit-gates"], **common)
        if row.get("verified"):
            row["rounds_per_quote"] = row["measured_rounds"] / requests
            row["ms_per_quote"] = row["wall_median"] / requests * 1000
        payload["batching"].append(row)
        print(f"  Q={requests:3d}  rounds={row.get('measured_rounds')}  "
              f"rounds/quote={row.get('rounds_per_quote')}  "
              f"ms/quote={row.get('ms_per_quote')}", flush=True)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
