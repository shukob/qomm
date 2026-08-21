#!/usr/bin/env python3
"""One circuit for every market, with the requested market kept secret.

Two things are measured. What it costs to serve A assets from one circuit, and
whether the wire trace changes with which asset was asked for. If it changed,
running one job per market would be no worse, and the whole construction would
be pointless.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts import hosts  # noqa: E402

HERE = Path(__file__).resolve().parent


def run(root: Path, **kw) -> dict:
    cmd = [sys.executable, str(HERE / "run_qomm.py"), "--mp-spdz-root", str(root)]
    for key, value in kw.items():
        cmd += [f"--{key.replace('_', '-')}", str(value)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"error": "unparseable", "stderr": proc.stderr[-800:], **kw}
    payload.get("circuit", {}).pop("compile_log", None)
    return payload


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mp-spdz-root", type=Path,
                    default=Path(os.environ.get("MP_SPDZ_ROOT", "")))
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--n-mm", type=int, default=16)
    ap.add_argument("--bit-length", type=int, default=31)
    ap.add_argument("--assets", type=int, nargs="+", default=[1, 2, 4, 8, 16])
    ap.add_argument("--delay-ms", type=float, default=1.0)
    ap.add_argument("--repeats", type=int, default=3)
    args = ap.parse_args()

    print("== cost of serving A assets from one circuit ==", flush=True)
    scaling = []
    for assets in args.assets:
        row = run(args.mp_spdz_root, n_mm=args.n_mm, bit_length=args.bit_length,
                  n_assets=assets, user_asset=0, delay_ms=args.delay_ms,
                  repeats=args.repeats, mode="rfq")
        scaling.append(row)
        print(f"  assets={assets:3d}  rounds={row.get('measured_rounds')}  "
              f"mb={row.get('measured_mb')}  median={row.get('wall_median')}  "
              f"ok={row.get('verified')}", flush=True)

    print("== does the trace change with which asset was requested? ==", flush=True)
    assets = max(args.assets)
    probes = []
    for requested in range(min(assets, 8)):
        row = run(args.mp_spdz_root, n_mm=args.n_mm, bit_length=args.bit_length,
                  n_assets=assets, user_asset=requested, delay_ms=args.delay_ms,
                  repeats=args.repeats, mode="rfq")
        probes.append(row)
        print(f"  requested asset {requested}: rounds={row.get('measured_rounds')} "
              f"mb={row.get('measured_mb')} median={row.get('wall_median')} "
              f"ok={row.get('verified')}", flush=True)

    good = [p for p in probes if p.get("verified")]
    rounds = {p["measured_rounds"] for p in good}
    megabytes = {p["measured_mb"] for p in good}
    times = [p["wall_median"] for p in good]
    winners = {p["verify_detail"] for p in good}
    summary = {
        "assets_probed": len(good),
        "identical_rounds": len(rounds) == 1,
        "identical_bytes": len(megabytes) == 1,
        "rounds": sorted(rounds), "megabytes": sorted(megabytes),
        "timing_gap_s": (max(times) - min(times)) if times else None,
        "distinct_answers": len(winners),
        "all_verified": len(good) == len(probes),
    }
    print(f"  identical rounds={summary['identical_rounds']} "
          f"bytes={summary['identical_bytes']} "
          f"timing spread={summary['timing_gap_s']:.4f}s "
          f"distinct answers={summary['distinct_answers']}", flush=True)

    payload = {"host": hosts.this_host(),
               "config": {k: (str(v) if isinstance(v, Path) else v)
                          for k, v in vars(args).items()},
               "scaling": scaling, "asset_probes": probes, "obliviousness": summary}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
