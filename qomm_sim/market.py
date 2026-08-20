"""Reference market, order flow and market-maker behaviour for the QOMM study.

The pricing rule implemented here is the same function the MP-SPDZ circuit
evaluates:

    ask_i = mid_i + half_i + slope_i * x + invcoef_i * inv_i
    bid_i = mid_i - half_i - slope_i * x + invcoef_i * inv_i

so a simulation result and a circuit result can be checked against each other.

All quantities are integers: prices in ticks, sizes in lots.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

SIZE_BUCKETS = ((1, 20), (21, 100), (101, 400))

# Inventory is carried in lots; the price skew it induces is measured in ticks,
# so the raw inventory is divided by this before the policy coefficient applies.
INV_SCALE = 32
BUCKET_NAMES = ("small", "medium", "large")


def size_bucket(size: int) -> int:
    for index, (lo, hi) in enumerate(SIZE_BUCKETS):
        if lo <= size <= hi:
            return index
    return len(SIZE_BUCKETS) - 1


@dataclass(frozen=True)
class SimConfig:
    steps: int = 48_000          # 50 ms per step -> 40 minutes of trading
    step_ms: int = 50
    n_mm: int = 16
    n_entities: int = 24
    wallets_per_entity: int = 3
    ref_mid0: int = 100_000      # ticks
    sigma_ticks: float = 6.0     # per-step volatility of the reference mid
    arrival_rate: float = 0.15   # requests per step across all entities (~3/s)
    informed_base: float = 0.30
    informed_ar: float = 0.995
    informed_sd: float = 0.05
    informed_edge_ticks: float = 22.0   # expected mid move that informed flow predicts
    window_steps: int = 1200     # disclosure window = 60 s
    seed: int = 20260818


@dataclass(frozen=True)
class Request:
    step: int
    entity: int
    wallet: int
    size: int
    direction: int               # 0 = user buys, 1 = user sells
    informed: bool
    signal: int                  # informed traders' view of the coming mid move


@dataclass
class MarketMaker:
    mm_id: int
    base_half: int
    slope: int
    inv_coef: int
    max_qty: int
    kappa: float                 # adverse-selection loading on the half spread
    inv_limit: int
    inventory: int = 0
    fills: int = 0
    realized_pnl: float = 0.0
    open_positions: list = field(default_factory=list)
    quoting: bool = True
    skew_cap: int | None = None

    def half_spread(self, phi_hat: float, size: int) -> int:
        """Half spread = fixed cost + adverse-selection premium.

        The premium is proportional to the maker's *estimate* of the informed
        fraction. A better estimate is worth money, which is the channel through
        which public market information can improve market-maker profitability.
        """
        premium = self.kappa * max(0.0, phi_hat) * math.sqrt(max(1, size))
        return self.base_half + int(round(premium))

    def quote(self, ref_mid: int, size: int, phi_hat: float) -> tuple[int, int]:
        half = self.half_spread(phi_hat, size)
        depth = self.slope * size
        skew = self.inv_coef * (self.inventory // INV_SCALE)
        if self.skew_cap is not None:
            # A conditional on a secret, which the rule language already allows
            # through min and max. Kept optional because whether it is worth its
            # six rounds is a measurement, not a preference.
            skew = max(-self.skew_cap, min(self.skew_cap, skew))
        ask = ref_mid + half + depth + skew
        bid = ref_mid - half - depth + skew
        return ask, bid

    def eligible(self, size: int) -> bool:
        return self.quoting and size <= self.max_qty and abs(self.inventory) < self.inv_limit


class ReferenceMarket:
    """Public reference mid plus a latent informed-flow intensity."""

    def __init__(self, cfg: SimConfig, seed: int):
        rng = random.Random(seed)
        self.cfg = cfg
        self.mid = [cfg.ref_mid0]
        self.phi = [cfg.informed_base]
        phi = cfg.informed_base
        mid = float(cfg.ref_mid0)
        for _ in range(cfg.steps):
            mid += rng.gauss(0.0, cfg.sigma_ticks)
            self.mid.append(int(round(mid)))
            phi = (cfg.informed_base
                   + cfg.informed_ar * (phi - cfg.informed_base)
                   + rng.gauss(0.0, cfg.informed_sd))
            phi = min(0.95, max(0.02, phi))
            self.phi.append(phi)

    def move(self, step: int, horizon: int) -> int:
        end = min(step + horizon, len(self.mid) - 1)
        return self.mid[end] - self.mid[step]


def build_market_makers(cfg: SimConfig, seed: int) -> list[MarketMaker]:
    rng = random.Random(seed)
    mms = []
    for i in range(cfg.n_mm):
        mms.append(MarketMaker(
            mm_id=i,
            base_half=rng.randint(6, 18),
            slope=rng.choice([0, 0, 1, 1, 2]),
            inv_coef=rng.choice([0, 1, 1, 2]),
            max_qty=rng.choice([100, 200, 400, 400]),
            kappa=rng.uniform(1.5, 4.0),
            inv_limit=rng.choice([600, 900, 1200]),
        ))
    return mms


def build_requests(cfg: SimConfig, market: ReferenceMarket, seed: int) -> list[Request]:
    """One shared request stream. Every arm replays exactly this stream."""
    rng = random.Random(seed)
    requests: list[Request] = []
    # entity activity levels are heterogeneous: a few large entities dominate
    weights = [rng.paretovariate(1.6) for _ in range(cfg.n_entities)]
    total = sum(weights)
    weights = [w / total for w in weights]
    for step in range(cfg.steps):
        if rng.random() >= cfg.arrival_rate:
            continue
        entity = _weighted_choice(rng, weights)
        wallet = entity * cfg.wallets_per_entity + rng.randrange(cfg.wallets_per_entity)
        bucket = rng.choices((0, 1, 2), weights=(0.55, 0.33, 0.12))[0]
        lo, hi = SIZE_BUCKETS[bucket]
        size = rng.randint(lo, hi)
        informed = rng.random() < market.phi[step]
        if informed:
            future = market.move(step, 20)
            direction = 0 if future > 0 else 1     # informed buy ahead of a rise
            signal = future
        else:
            direction = rng.randrange(2)
            signal = 0
        requests.append(Request(step, entity, wallet, size, direction, informed, signal))
    return requests


def _weighted_choice(rng: random.Random, weights: list[float]) -> int:
    draw = rng.random()
    acc = 0.0
    for index, w in enumerate(weights):
        acc += w
        if draw <= acc:
            return index
    return len(weights) - 1
