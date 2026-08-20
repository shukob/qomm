#!/usr/bin/env python3
"""What node placement costs when the nodes are not all the same distance away.

The delay proxy applied one figure to every link, which models seven nodes at
equal distance --- the one arrangement no deployment has. A round waits on the
slowest link it uses, not the average, so the prediction is that one distant
node costs close to what seven do, and that bringing the other six home buys
almost nothing. That is a different deployment recommendation from "co-locate
and it is six times faster", so it is worth measuring rather than reasoning
about.

Four placements, each verified against the plaintext answer, because a timing
result from a run that computed the wrong thing is not a timing result.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.hosts import this_host
from scripts.measure import exact, render, summarise          # noqa: E402                                          # noqa: E402


def placements(near: float, far: float, n_parties: int) -> list[dict]:
    return [
        {"name": "all near", "per_party": [near] * n_parties},
        {"name": "one far", "per_party": [near] * (n_parties - 1) + [far]},
        {"name": "one near", "per_party": [far] * (n_parties - 1) + [near]},
        {"name": "all far", "per_party": [far] * n_parties},
    ]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mp-spdz-root", default=str(Path.home() / "work/qomm/MP-SPDZ"))
    ap.add_argument("--out", type=Path, default=ROOT / "artifacts" / "placement.json")
    ap.add_argument("--near", type=float, default=1.0)
    ap.add_argument("--far", type=float, default=15.0)
    ap.add_argument("--n-mm", type=int, default=16)
    ap.add_argument("--n-parties", type=int, default=7)
    ap.add_argument("--bit-length", type=int, default=31)
    ap.add_argument("--repeats", type=int, default=3)
    args = ap.parse_args()

    result = {"host": this_host(), "near_ms": args.near, "far_ms": args.far,
              "n_mm": args.n_mm, "n_parties": args.n_parties,
              "bit_length": args.bit_length, "repeats": args.repeats, "rows": []}

    for case in placements(args.near, args.far, args.n_parties):
        walls, rounds, verified = [], [], []
        for _ in range(args.repeats):
            out = Path("/tmp") / f"placement_{case['name'].replace(' ', '_')}.json"
            cmd = [sys.executable, str(ROOT / "scripts" / "run_qomm.py"),
                   "--mp-spdz-root", args.mp_spdz_root,
                   "--n-mm", str(args.n_mm), "--n-parties", str(args.n_parties),
                   "--bit-length", str(args.bit_length), "--repeats", "1",
                   "--per-party-ms", *[str(x) for x in case["per_party"]],
                   "--out", str(out)]
            t = time.perf_counter()
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                raise RuntimeError(f"{case['name']} failed:\n{proc.stderr[-800:]}")
            payload = json.loads(out.read_text())
            samples = payload.get("samples") or []
            walls.append(payload.get("wall_median")
                         or statistics.median(s["wall_seconds"] for s in samples))
            rounds.append(payload.get("party_rounds"))
            # a timing result from a run that computed the wrong thing is not one
            verified.append(bool(payload.get("verified")))
            del t
        row = {"placement": case["name"], "per_party_ms": case["per_party"],
               "wall_s": summarise(walls),
               # The round count is compiled, not measured; it is identical
               # across placements by construction, which is the point.
               "rounds": exact(rounds[0]), "verified": all(verified)}
        result["rows"].append(row)
        print(f"  {row['placement']:10} {render(row['wall_s'], 3, ' s')}  "
              f"rounds {row['rounds']['exact']}  verified={row['verified']}", flush=True)

    base = next(r for r in result["rows"] if r["placement"] == "all near")
    worst = next(r for r in result["rows"] if r["placement"] == "all far")
    one = next(r for r in result["rows"] if r["placement"] == "one far")
    spread = worst["wall_median_s"] - base["wall_median_s"]
    result["one_far_share_of_all_far"] = (
        (one["wall_median_s"] - base["wall_median_s"]) / spread if spread else None)
    print(f"\none distant node costs "
          f"{100 * (result['one_far_share_of_all_far'] or 0):.0f}% of moving them all")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
