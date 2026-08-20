#!/usr/bin/env python3
"""How much of the headline result is the protocol, and how much is the adversary.

The primary claim compares two numbers: how well an observer detects that an
entity asked for something and settled nothing, with and without the design.
Only one of them is a property of the protocol. The other depends on how much of
the wallet-to-entity map the adversary already holds, which is a parameter we
had fixed at 0.5 with nothing behind the number, and which turns out to set
almost the whole size of the gap.

So sweep it. If the query-oblivious arm holds at 0.500 across the range while
only the baseline moves, the result is a statement about the protocol and the
unknown parameter is confined to the size of the gap rather than its existence.

The generated market and a real tape are both swept, because the point of the
sweep is that it is the adversary and not the market that moves the baseline,
and that is a claim about both.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qomm_sim import attackers as atk                                        # noqa: E402
from qomm_sim.engine import run_arm                                          # noqa: E402
from qomm_sim.experiment import DPParams, build_probes, make_disclosure       # noqa: E402
from qomm_sim.market import (                                                # noqa: E402
    ReferenceMarket, SimConfig, build_market_makers, build_requests,
)
from qomm_sim.tapes import TapeMarket, load_bybit, requests_from_tape         # noqa: E402
from scripts.hosts import this_host                                          # noqa: E402


def one_market(cfg: SimConfig, tape_path: Path | None, step_ms: int, entities: int):
    """Either the generated market or a real tape, on the same interface."""
    if tape_path is None:
        market = ReferenceMarket(cfg, cfg.seed)
        return market, build_requests(cfg, market, cfg.seed + 2), cfg, {"source": "generated"}
    tape = load_bybit(tape_path, cfg, steps=cfg.steps, step_ms=step_ms)
    market = TapeMarket(cfg, tape, seed=cfg.seed)
    requests, cfg, meta = requests_from_tape(
        cfg, market, tape, synthetic_entities=entities, seed=cfg.seed + 2)
    return market, requests, cfg, meta


def sweep(tape_path: Path | None, protocols, rhos, seeds, steps, window_steps,
          step_ms, entities) -> dict:
    rows: dict[tuple, list] = {}
    meta = {}
    for seed in seeds:
        cfg = SimConfig(steps=steps, window_steps=window_steps, seed=seed)
        market, requests, cfg, meta = one_market(cfg, tape_path, step_ms, entities)
        makers = build_market_makers(cfg, cfg.seed + 1)
        probes = build_probes(cfg, cfg.seed + 3, 6)
        for protocol in protocols:
            result = run_arm(cfg, market, list(requests), makers, protocol,
                             make_disclosure("A_none", cfg, DPParams()),
                             seed=cfg.seed + 5, probes=probes, reactive=False)
            for rho in rhos:
                report = atk.passive_observer(result, cfg, linkage_rho=rho)
                if report.auc is not None:
                    rows.setdefault((protocol, rho), []).append(
                        (report.auc, report.extra["entities_covered"], report.n_examples))
    out = []
    for (protocol, rho), values in sorted(rows.items()):
        aucs = [v[0] for v in values]
        out.append({
            "protocol": protocol, "linkage_rho": rho,
            "auc_mean": statistics.fmean(aucs),
            "auc_min": min(aucs), "auc_max": max(aucs),
            "entities_covered": statistics.fmean(v[1] for v in values),
            "cells_scored": statistics.fmean(v[2] for v in values),
            "seeds": len(aucs),
        })
    return {"meta": meta, "rows": out}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=ROOT / "artifacts" / "rho_sweep.json")
    ap.add_argument("--tape", type=Path, default=None,
                    help="a Bybit symbol-day; omit to sweep the generated market only")
    ap.add_argument("--tape-step-ms", type=int, default=1000)
    ap.add_argument("--tape-entities", type=int, default=24)
    ap.add_argument("--rhos", type=float, nargs="+",
                    default=[0.0, 0.05, 0.12, 0.25, 0.5, 0.75, 1.0])
    ap.add_argument("--protocols", nargs="+",
                    default=["qomm_rfq", "plain_rfq", "plain_rfm", "plain_rfs"])
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--seed0", type=int, default=20260818)
    ap.add_argument("--steps", type=int, default=48_000)
    ap.add_argument("--window-steps", type=int, default=1_200)
    args = ap.parse_args()

    seeds = [args.seed0 + i for i in range(args.seeds)]
    result = {"host": this_host(), "python": platform.python_version(),
              "rhos": args.rhos, "seeds": args.seeds, "arms": {}}

    result["arms"]["generated"] = sweep(
        None, args.protocols, args.rhos, seeds, args.steps, args.window_steps,
        args.tape_step_ms, args.tape_entities)
    print("generated market:")
    for row in result["arms"]["generated"]["rows"]:
        if row["protocol"] in ("qomm_rfq", "plain_rfq"):
            print(f"  {row['protocol']:10} rho={row['linkage_rho']:<5} "
                  f"auc {row['auc_mean']:.4f}  firms covered "
                  f"{row['entities_covered']:.1f}", flush=True)

    if args.tape:
        # a tape is shorter than the generated horizon, so it gets its own shape
        result["arms"]["tape"] = sweep(
            args.tape, args.protocols, args.rhos, seeds, 2_400, 60,
            args.tape_step_ms, args.tape_entities)
        print(f"\n{args.tape.name}:")
        for row in result["arms"]["tape"]["rows"]:
            if row["protocol"] in ("qomm_rfq", "plain_rfq"):
                print(f"  {row['protocol']:10} rho={row['linkage_rho']:<5} "
                      f"auc {row['auc_mean']:.4f}", flush=True)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
