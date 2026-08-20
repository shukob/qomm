"""A small bench for turning one knob at a time and seeing what moves.

The scripts under `scripts/` run whole experiments and write artifacts, which is
what the paper and the figures are built from. This is the other mode: one arm
takes 0.13 s at the published size, so the interesting questions --- what happens
if the adversary knows more, if the market is thinner, if the disclosure budget
is larger --- can be asked and answered while you are still thinking about them.

Two rules keep this from becoming a second source of truth.

Nothing here re-implements the simulation. `build` and `arm` assemble the same
objects `run_sim_matrix.py` assembles, in the same order, from the same
functions; if a result from this bench disagreed with an artifact at the same
settings, that would be a bug here and not a finding.

And the market is built once and shared across arms. Rebuilding it per arm would
give each protocol its own order flow, and the comparison between protocols is
the whole point --- the arms have to see the same requests or the difference
between them includes the difference between their markets.
"""

from __future__ import annotations

import copy
import dataclasses
from pathlib import Path
from typing import Any, Iterable, Sequence

from . import attackers as atk
from .disclosure import DPDisclosure, EntityAccountant
from .engine import run_arm
from .experiment import DPParams, build_probes, make_disclosure
from .market import (
    MarketMaker, ReferenceMarket, SimConfig, build_market_makers, build_requests,
)
from .tapes import TapeMarket, load_bybit, load_uniswapx, requests_from_tape

PROTOCOLS = ("plain_rfq", "plain_rfm", "plain_rfs", "qomm_rfq", "qomm_rfm", "qomm_rfs")
DISCLOSURES = ("A_none", "B_threshold", "C_dp")


@dataclasses.dataclass
class Setup:
    """One market and its participants, ready for any number of arms."""

    cfg: SimConfig
    market: Any
    makers: list[MarketMaker]
    requests: list
    probes: list
    meta: dict

    def describe(self) -> str:
        source = self.meta.get("source", "generated")
        rate = len(self.requests) / max(1, self.cfg.steps * self.cfg.step_ms / 1000)
        return (f"{source}: {len(self.requests):,} requests over {self.cfg.steps:,} steps "
                f"({rate:.2f}/s), {self.cfg.n_entities} entities, {self.cfg.n_mm} makers")


def build(*, steps: int = 48_000, window_steps: int = 1_200, seed: int = 20260818,
          n_mm: int = 16, n_entities: int = 24, arrival_rate: float = 0.15,
          tape: str | Path | None = None, tape_kind: str = "bybit",
          tape_step_ms: int = 1_000, tape_step_blocks: int = 150,
          tape_entities: int | None = 24, probes_per_window: int = 6) -> Setup:
    """Assemble a market. Pass `tape` to use a real one instead of a generated one.

    `arrival_rate` only reaches a generated market; a tape arrives at whatever
    rate it arrived at, which is usually the point of using one.
    """
    cfg = SimConfig(steps=steps, window_steps=window_steps, seed=seed,
                    n_mm=n_mm, n_entities=n_entities, arrival_rate=arrival_rate)
    if tape is None:
        market = ReferenceMarket(cfg, cfg.seed)
        requests = build_requests(cfg, market, cfg.seed + 2)
        meta = {"source": "generated"}
    else:
        path = Path(tape)
        if tape_kind == "bybit":
            loaded = load_bybit(path, cfg, steps=steps, step_ms=tape_step_ms)
        else:
            loaded = load_uniswapx(path, cfg, steps=steps, step_blocks=tape_step_blocks)
        market = TapeMarket(cfg, loaded, seed=cfg.seed)
        requests, cfg, meta = requests_from_tape(
            cfg, market, loaded, synthetic_entities=tape_entities, seed=cfg.seed + 2)
    return Setup(cfg=cfg, market=market,
                 makers=build_market_makers(cfg, cfg.seed + 1),
                 requests=requests,
                 probes=build_probes(cfg, cfg.seed + 3, probes_per_window),
                 meta=meta)


def _mechanism(setup: Setup, disclosure: str, epsilon: float, debias: bool,
               signed_sensitivity: float):
    dp = DPParams(epsilon_per_window=epsilon)
    if disclosure != "C_dp":
        return make_disclosure(disclosure, setup.cfg, dp)
    accountants = {e: EntityAccountant(dp.epsilon_total)
                   for e in range(setup.cfg.n_entities)}
    return DPDisclosure(dp.epsilon_per_window, dp.request_cap, dp.volume_cap,
                        accountants, debias=debias,
                        signed_sensitivity_factor=signed_sensitivity)


def arm(setup: Setup, *, protocol: str = "plain_rfq", disclosure: str = "A_none",
        epsilon: float = 1.0, reactive: bool = False, rho: float = 0.5,
        debias: bool = True, signed_sensitivity: float = 1.0) -> dict:
    """Run one arm and report what the attacks and the economics say.

    `rho` is the adversary's prior attribution, which is evaluated after the run
    rather than during it --- the same simulation supports every value of it, so
    sweeping the adversary costs nothing beyond the scoring.
    """
    result = run_arm(setup.cfg, setup.market, list(setup.requests),
                     [copy.deepcopy(m) for m in setup.makers], protocol,
                     _mechanism(setup, disclosure, epsilon, debias, signed_sensitivity),
                     seed=setup.cfg.seed + 5, probes=setup.probes, reactive=reactive)
    summary = result.summary()
    passive = atk.passive_observer(result, setup.cfg, linkage_rho=rho)
    informed = atk.external_info_observer(result, setup.cfg, setup.market)
    return {
        "protocol": protocol, "disclosure": disclosure, "epsilon": epsilon,
        "rho": rho, "reactive": reactive,
        "fill_rate": summary["fill_rate"],
        "mm_pnl_per_fill": summary["mm_pnl_per_fill"],
        # "suppressed" means the mechanism declined to publish. With no
        # disclosure there is nothing to decline, so reporting 1.0 there reads
        # as "always withheld" when it means "never offered"
        "suppression_rate": (summary.get("suppression_rate")
                             if disclosure != "A_none" else None),
        "detection_auc": passive.auc,
        "detection_cells": passive.n_examples,
        "entities_covered": passive.extra.get("entities_covered"),
        "informed_auc": informed.auc,
        "_result": result,
    }


def sweep(setup: Setup, over: str, values: Iterable, **fixed) -> list[dict]:
    """Turn one knob and hold the rest still.

    Returns the rows in the order the values were given, so a plot of them reads
    left to right the way the sweep was written.
    """
    rows = []
    for value in values:
        rows.append(arm(setup, **{**fixed, over: value}))
    return rows


def compare(setup: Setup, protocols: Sequence[str] = ("qomm_rfq", "plain_rfq"),
            **fixed) -> list[dict]:
    """The same market seen by several protocols, which is the study's whole shape."""
    return [arm(setup, protocol=protocol, **fixed) for protocol in protocols]


def table(rows: Sequence[dict], columns: Sequence[str] = (
        "protocol", "disclosure", "rho", "detection_auc", "fill_rate",
        "mm_pnl_per_fill", "suppression_rate")) -> str:
    """A plain table, so a result can be read without a plotting library."""
    widths = {c: max(len(c), 11) for c in columns}
    out = ["  ".join(c.rjust(widths[c]) for c in columns)]
    for row in rows:
        cells = []
        for column in columns:
            value = row.get(column)
            if value is None:
                cells.append("n/a".rjust(widths[column]))
            elif isinstance(value, float):
                cells.append(f"{value:.4f}".rjust(widths[column]))
            else:
                cells.append(str(value).rjust(widths[column]))
        out.append("  ".join(cells))
    return "\n".join(out)


def tapes(root: Path | None = None) -> list[Path]:
    """Whatever real symbol-days this checkout has, busiest first by file size."""
    root = root or Path(__file__).resolve().parent.parent / "artifacts" / "tapes"
    if not root.exists():
        return []
    return sorted((p for p in root.glob("*.csv")), key=lambda p: -p.stat().st_size)
