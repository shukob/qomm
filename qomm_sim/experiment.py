"""Phase-3 comparison driver.

Two layers, reported separately, as the proposal requires:

  layer 1 (replay)    every arm sees the identical request stream, the identical
                      maker policies and the identical random draws. Only the
                      leakage and the disclosure differ. This isolates privacy
                      and circuit cost.
  layer 2 (reactive)  only the reference price path and the random seed are
                      shared. Users and makers react to what their arm lets them
                      see, so order flow itself differs between arms. This is the
                      only layer in which an economic effect can appear.

Mixing the two layers would either hide the economic effect or make the privacy
comparison unfair, so the outputs are kept apart.
"""

from __future__ import annotations

import json
import random
from dataclasses import asdict, dataclass
from pathlib import Path

from . import attackers as atk
from .disclosure import (
    DPDisclosure, DisclosureMechanism, EntityAccountant, NoDisclosure, ThresholdDisclosure,
)
from .engine import PLAIN_PROTOCOLS, QOMM_PROTOCOLS, Probe, run_arm
from .market import ReferenceMarket, SimConfig, build_market_makers, build_requests
from .tapes import Tape, TapeMarket, requests_from_tape


@dataclass(frozen=True)
class DPParams:
    epsilon_per_window: float = 1.0
    epsilon_total: float = 20.0
    request_cap: int = 3
    volume_cap: int = 300
    # Correcting the absolute-value skew is the default now that its cause is
    # known; the uncorrected arm stays reachable so the negative result can be
    # reproduced against its own fix rather than against nothing.
    debias: bool = True


def make_disclosure(name: str, cfg: SimConfig, dp: DPParams) -> DisclosureMechanism:
    if name == "A_none":
        return NoDisclosure()
    if name == "B_threshold":
        return ThresholdDisclosure()
    if name == "C_dp":
        accountants = {e: EntityAccountant(dp.epsilon_total) for e in range(cfg.n_entities)}
        return DPDisclosure(dp.epsilon_per_window, dp.request_cap, dp.volume_cap,
                            accountants, debias=dp.debias)
    raise ValueError(name)


def build_probes(cfg: SimConfig, seed: int, per_window: int = 6,
                 probe_size: int = 50) -> list[Probe]:
    """A probing entity spends its whole allowance, evenly spread."""
    probes = []
    n_windows = cfg.steps // cfg.window_steps
    attacker_entity = cfg.n_entities          # outside the honest population
    for window in range(n_windows):
        for k in range(per_window):
            step = window * cfg.window_steps + int((k + 0.5) * cfg.window_steps / per_window)
            probes.append(Probe(
                step=min(step, cfg.steps - 1),
                size=probe_size,
                wallet=10_000 + k,
                entity=attacker_entity,
            ))
    return probes


def run_matrix(
    cfg: SimConfig,
    dp: DPParams,
    protocols: tuple[str, ...],
    disclosures: tuple[str, ...],
    layer: str,
    probe_per_window: int = 6,
    tape: Tape | None = None,
    synthetic_entities: int | None = None,
) -> list[dict]:
    """Run every arm against one market.

    With a tape the price path, the arrivals, the sizes and the directions are
    observed rather than drawn, and the configuration has to follow the data:
    the horizon becomes the tape's, and the entity count becomes however many
    the tape actually contains. Makers stay generated either way, because a
    maker's pricing rule is not observable and is the design space being swept.
    """
    tape_meta = None
    if tape is None:
        market = ReferenceMarket(cfg, cfg.seed)
        tape_requests = None
    else:
        market = TapeMarket(cfg, tape)
        tape_requests, cfg, tape_meta = requests_from_tape(
            cfg, market, tape, synthetic_entities=synthetic_entities,
            seed=cfg.seed + 2)
    makers = build_market_makers(cfg, cfg.seed + 1)
    probes = build_probes(cfg, cfg.seed + 3, probe_per_window)
    rows = []
    for protocol in protocols:
        for name in disclosures:
            # layer 1 replays one shared stream; layer 2 lets flow differ per arm
            requests = (list(tape_requests) if tape_requests is not None
                        else build_requests(cfg, market, cfg.seed + 2))
            disclosure = make_disclosure(name, cfg, dp)
            result = run_arm(cfg, market, requests, makers, protocol, disclosure,
                             seed=cfg.seed + 5, probes=probes,
                             reactive=(layer == "reactive"))
            row = result.summary()
            row["layer"] = layer
            if tape_meta is not None:
                row["tape"] = tape_meta
            reports = [
                atk.passive_observer(result, cfg),
                atk.pretrade_attributes(result, cfg),
                atk.window_shift_observer(result, cfg),
                atk.probing_entity(result, cfg, probe_budget=len(probes)),
                atk.colluding_wallets(result, cfg, wallet_limit=4, entity_limit=4),
                atk.external_info_observer(result, cfg, market),
            ]
            row["attacks"] = [r.as_dict() for r in reports]
            rows.append(row)
    return rows


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--steps", type=int, default=48_000)
    ap.add_argument("--n-mm", type=int, default=16)
    ap.add_argument("--n-entities", type=int, default=24)
    ap.add_argument("--arrival-rate", type=float, default=0.15)
    ap.add_argument("--window-steps", type=int, default=1200)
    ap.add_argument("--epsilon-per-window", type=float, default=1.0)
    ap.add_argument("--epsilon-total", type=float, default=20.0)
    ap.add_argument("--seed", type=int, default=20260818)
    ap.add_argument("--layers", nargs="+", default=["replay", "reactive"])
    ap.add_argument("--protocols", nargs="+",
                    default=list(PLAIN_PROTOCOLS) + list(QOMM_PROTOCOLS))
    ap.add_argument("--disclosures", nargs="+", default=["A_none", "B_threshold", "C_dp"])
    args = ap.parse_args(argv)

    cfg = SimConfig(
        steps=args.steps, n_mm=args.n_mm, n_entities=args.n_entities,
        arrival_rate=args.arrival_rate, window_steps=args.window_steps, seed=args.seed,
    )
    dp = DPParams(epsilon_per_window=args.epsilon_per_window, epsilon_total=args.epsilon_total)
    payload = {"config": asdict(cfg), "dp": asdict(dp), "rows": []}
    for layer in args.layers:
        payload["rows"].extend(run_matrix(
            cfg, dp, tuple(args.protocols), tuple(args.disclosures), layer))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {args.out} ({len(payload['rows'])} arms)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
