#!/usr/bin/env python3
"""Run the demo. One command, no install, one URL per person.

    python3 scripts/serve_demo.py

Then open the address it prints. The first browser to arrive gets the lobby and
picks a seat; every seat nobody picks runs itself, so one person with one laptop
sees a working market immediately and a room of nine sees the same market with
people in it. A seat can also be gone to directly, which is what to paste into a
chat when handing seats out:

    http://<host>:8800/?seat=node:3&label=Rin
    http://<host>:8800/?seat=observer          the screen at the front

`--engine mpc` runs each round in MP-SPDZ instead of in the demo's own share
layer. It needs a built MP-SPDZ and it is much slower per round, which is the
honest reason the default is the other one --- and the badge in the corner of
every page says which is running, because a demo that let you wonder would be
worth nothing.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qomm_demo.room import DEFAULT_ASSETS, Room          # noqa: E402
from qomm_demo.server import Demo                        # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0",
                    help="0.0.0.0 so other machines on the same network can "
                         "reach it, which is the point of having seats")
    ap.add_argument("--port", type=int, default=8800)
    ap.add_argument("--makers", type=int, default=8)
    ap.add_argument("--nodes", type=int, default=9,
                    help="9 with a threshold of 2 is the design point: n >= 4T+1 "
                         "is what lets a wrong share in a multiplication be "
                         "corrected rather than only detected")
    ap.add_argument("--threshold", type=int, default=2)
    ap.add_argument("--round-seconds", type=float, default=8.0)
    ap.add_argument("--step-ms", type=int, default=350,
                    help="how long to hold each phase on screen. Pacing for the "
                         "room, not protocol time; 0 to turn it off")
    ap.add_argument("--no-auto-rounds", action="store_true",
                    help="wait for somebody to press send instead of running on "
                         "a clock")
    ap.add_argument("--no-input-check", action="store_true",
                    help="start with the commitment check off, so a node feeding "
                         "a share it was not dealt goes unnoticed")
    ap.add_argument("--engine", choices=("sim", "mpc"), default="sim")
    ap.add_argument("--mp-spdz-root", default=None)
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    if args.nodes < 4 * args.threshold + 1:
        print(f"note: {args.nodes} nodes with a threshold of {args.threshold} is "
              f"below n >= 4T+1, so a wrong share in a multiplication will be "
              f"detected and not corrected. That is a fine thing to demonstrate "
              f"deliberately and a confusing one to hit by accident.")

    engine = None
    if args.engine == "mpc":
        from qomm_demo.mpc import MpcEngine
        engine = MpcEngine(args.mp_spdz_root, n_parties=args.nodes,
                           threshold=args.threshold, n_makers=args.makers,
                           n_assets=len(DEFAULT_ASSETS),
                           ref_table=[a.reference for a in DEFAULT_ASSETS])

    room = Room(n_makers=args.makers, n_nodes=args.nodes,
                threshold=args.threshold, engine=engine,
                input_check=not args.no_input_check, seed=args.seed)
    demo = Demo(room, engine=engine, round_seconds=args.round_seconds,
                step_ms=args.step_ms, auto_rounds=not args.no_auto_rounds,
                seed=args.seed)
    print(f"QOMM demo --- {args.makers} makers, {args.nodes} nodes, "
          f"threshold {args.threshold}, engine {args.engine}", flush=True)
    try:
        asyncio.run(demo.serve(args.host, args.port))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
