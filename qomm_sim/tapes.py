"""Real order flow in place of the generated kind.

`market.py` draws everything: the reference mid is a Gaussian walk, arrivals are
Poisson at three per second, entity activity is Pareto over twenty-four firms.
One of the rejection criteria written down before any measurement was whether
the results survive a different data-generating rule, and the honest way to
settle that is to stop generating.

Two tapes, because no single source carries everything.

*UniswapX* is request-for-quote on chain. A fill names the swapper who asked and
the filler who won, which is the pair the simulator generates, and the venue
carried 8--23 distinct fillers throughout the 28 months measured --- so M=16 is
observed rather than chosen. It is also genuinely thin: 0.009--0.035 requests
per second against the simulator's 3, with most 60-second windows empty. That is
not a defect of the source, it is the thin-market case the second rejection
criterion asks about.

*Bybit* is a perpetual-futures tape, 220 symbols over three years. No identities,
but the density the simulator assumes and a measured 115x spread in liquidity
between the busiest and quietest symbol, which is the sweep the thin-market
criterion needs on the dense side.

What neither supplies is a maker's pricing rule, so `build_market_makers` stays
as it is: real policies are unobservable, and they are the design space the
study sweeps anyway.
"""

from __future__ import annotations

import dataclasses
import json
import statistics
from collections import Counter, defaultdict, deque
from pathlib import Path

from .market import Request, SimConfig

# Post-merge a slot is 12 seconds, so a 60-second disclosure window is exactly
# five blocks. Using block height as the clock avoids fetching a timestamp per
# fill --- about a million calls --- and avoids the drift that interpolating
# inside a chunk accumulates once slots are missed.
SECONDS_PER_BLOCK = 12

# Real trade sizes are far more skewed than the simulator's three buckets, so
# the rescale needs headroom above the largest bucket rather than a clip at it.
SIZE_CEILING = 100_000


@dataclasses.dataclass
class Tape:
    """One market's history, already on the simulator's step grid."""

    mid: list[int]                    # reference price per step, in ticks
    rows: list[tuple]                 # (step, address, size, direction)
    source: str
    meta: dict

    @property
    def steps(self) -> int:
        return len(self.mid) - 1


class TapeMarket:
    """A `ReferenceMarket` whose price path and informed fraction are measured.

    The generated version draws the informed fraction from an AR(1) and then
    decides each request's direction from the future it is allowed to see. A
    tape has no such flag --- nothing in a trade record says whether the trader
    knew something --- so it has to be estimated, and the estimate has to stay
    latent.

    Estimating it is straightforward. Uninformed flow agrees with the subsequent
    move half the time, so if a fraction `a` of requests agreed, the informed
    share is the excess, `2a - 1`. Keeping it latent matters more than it looks:
    labelling a request informed whenever its signed move cleared a threshold
    makes the label a deterministic function of exactly the quantity attacker 5
    scores on, and that attacker then reports an AUC of 1.0 --- a measurement of
    the labelling rule, not of the attack. So informedness is assigned by draw
    among the requests that agreed, at a rate that reproduces the estimated
    share, which is the same structure the generated arm has.
    """

    def __init__(self, cfg: SimConfig, tape: Tape, horizon: int = 20,
                 edge_percentile: float = 60.0, phi_window: int = 200,
                 seed: int = 0):
        self.cfg = cfg
        self.mid = tape.mid
        self.source = tape.source
        self.meta = dict(tape.meta)

        import random

        self.horizon = horizon
        rng = random.Random(seed)

        agreements = []
        for step, _addr, _size, direction in tape.rows:
            move = self.move(step, horizon)
            agreements.append(((move > 0) if direction == 0 else (move < 0)))
        rate = sum(agreements) / len(agreements) if agreements else 0.5
        self.agreement_rate = rate
        # uninformed flow agrees half the time; the excess is the informed share
        self.informed_share = min(1.0, max(0.0, 2.0 * rate - 1.0))
        mark = (self.informed_share / rate) if rate > 0 else 0.0

        labels: list[tuple[int, bool]] = []
        self.informed_flags: list[bool] = []
        for (step, _addr, _size, _direction), agreed in zip(tape.rows, agreements):
            flag = agreed and rng.random() < mark
            self.informed_flags.append(flag)
            labels.append((step, flag))
        # kept for reporting only; the size of a move no longer gates the label
        moves_sorted = sorted(abs(self.move(step, horizon)) for step, *_ in tape.rows)
        self.edge = (max(1, moves_sorted[min(len(moves_sorted) - 1,
                                             int(len(moves_sorted) * edge_percentile / 100.0))])
                     if moves_sorted else 1)

        # phi[t] is the share of informed requests in the trailing window, held
        # flat between arrivals because there is nothing to update in between.
        self.phi = [cfg.informed_base] * (len(self.mid))
        recent: deque[bool] = deque(maxlen=phi_window)
        cursor = 0
        for step in range(len(self.mid)):
            while cursor < len(labels) and labels[cursor][0] <= step:
                recent.append(labels[cursor][1])
                cursor += 1
            if recent:
                self.phi[step] = sum(recent) / len(recent)
        self.measured_phi = statistics.median(self.phi) if self.phi else None

    def move(self, step: int, horizon: int) -> int:
        end = min(step + horizon, len(self.mid) - 1)
        return self.mid[end] - self.mid[step]


def _rescale_sizes(raw: list[float], target_median: int, ceiling: int) -> list[int]:
    """Put real sizes on the simulator's lot scale without reshaping them.

    Absolute size is not comparable --- a tape is denominated in tokens or
    contracts, the simulator in lots --- but the shape is exactly what matters
    here, because the entity contribution caps and a maker's `max_qty` bite on
    the tail. A single multiplicative factor fixed by the median moves the
    distribution onto the right scale and leaves the tail where it is. Anything
    above the rail's ceiling is clipped, and how often that happens is recorded
    rather than hidden.
    """
    positive = [v for v in raw if v > 0]
    if not positive:
        return [1] * len(raw)
    factor = target_median / statistics.median(positive)
    out = []
    for value in raw:
        scaled = int(round(value * factor))
        out.append(max(1, min(ceiling, scaled)))
    return out


def _read_fills(path: Path) -> tuple[list[dict], list[tuple]]:
    """Split the collector's output into fills and its progress checkpoints."""
    fills, checkpoints = [], []
    with path.open() as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            if "checkpoint" in row:
                checkpoints.append((row["block"], row["checkpoint"]))
            elif row.get("legs"):
                fills.append(row)
    if not fills:
        raise ValueError(f"{path} has no fills with decoded legs; run the --amounts pass")
    fills.sort(key=lambda r: (r["block"], r["log_index"]))
    return fills, checkpoints


def _legs(fill: dict) -> tuple[dict, dict] | None:
    """The largest outgoing and incoming leg, or None for a fill we cannot read.

    Skipping is deliberate: a fill whose legs do not decode is a gap in the
    record, and inventing one would put a trade in the tape that never happened.
    """
    outs = [l for l in fill["legs"] if l["out"] and l["amount"] > 0]
    ins = [l for l in fill["legs"] if not l["out"] and l["amount"] > 0]
    if not outs or not ins:
        return None
    return (max(outs, key=lambda l: l["amount"]),
            max(ins, key=lambda l: l["amount"]))


def _choose_pair(fills: list[dict], path: Path,
                 pair: tuple[str, str] | None) -> tuple[frozenset, str, str, Counter]:
    """Pick one token pair and fix which token is the quote.

    Mixing pairs would make the price series meaningless: a ratio of USDC to
    ether and one of USDC to wrapped bitcoin are not points on one curve, and do
    not even share a decimal scale. Within a pair the two tokens are ordered by
    address and the smaller is the quote, so price, size and direction are stated
    against a fixed base regardless of which way a fill went.
    """
    counts: Counter = Counter()
    for fill in fills:
        both = _legs(fill)
        if both:
            counts[frozenset((both[0]["token"], both[1]["token"]))] += 1
    if not counts:
        raise ValueError(f"{path} has no fill with both legs readable")
    chosen = frozenset(pair) if pair else counts.most_common(1)[0][0]
    if len(chosen) != 2:
        raise ValueError(f"a pair needs two distinct tokens, got {sorted(chosen)}")
    quote, base = sorted(chosen)          # by address, so the roles never drift
    return chosen, quote, base, counts


def _price_path(prices: list[tuple[int, float]], total_steps: int,
                cfg: SimConfig, ceiling: int) -> list[int]:
    """Forward-filled implied price, anchored to the simulator's starting mid.

    This is a trade price and carries the spread, unlike the quote mid the
    generated version uses. It is the only reference this arm can have, since
    the venue's own executions are what define it. Normalising by the first
    observation cancels any constant factor from differing decimals.
    """
    by_step: dict[int, list[float]] = defaultdict(list)
    for step, price in prices:
        by_step[step].append(price)
    first = statistics.median(by_step[min(by_step)])
    mid, last = [], cfg.ref_mid0
    for step in range(total_steps + 1):
        if step in by_step:
            last = int(round(cfg.ref_mid0 * statistics.median(by_step[step]) / first))
        mid.append(max(1, min(ceiling, last)))
    return mid


def load_uniswapx(path: Path, cfg: SimConfig, *, steps: int | None = None,
                  step_blocks: int = 1, min_requests_per_entity: int = 1,
                  pair: tuple[str, str] | None = None) -> Tape:
    """Fills from `scripts/collect_uniswapx.py`, on the simulator's step grid."""
    fills, checkpoints = _read_fills(path)
    chosen, quote, base, pair_counts = _choose_pair(fills, path, pair)

    kept = []
    for fill in fills:
        both = _legs(fill)
        if both and frozenset((both[0]["token"], both[1]["token"])) == chosen:
            kept.append((fill, *both))
    if not kept:
        raise ValueError(f"no fills on the requested pair in {path}")

    base_block = kept[0][0]["block"]
    span = kept[-1][0]["block"] - base_block
    total_steps = steps if steps is not None else max(1, span // step_blocks)

    raw_sizes, rows_raw, prices = [], [], []
    for fill, sold, bought in kept:
        step = (fill["block"] - base_block) // step_blocks
        if step > total_steps:
            break
        amounts = {sold["token"]: sold["amount"], bought["token"]: bought["amount"]}
        # direction is stated from the taker's side, as the simulator states it:
        # 0 when the user ends up holding the base token
        direction = 0 if bought["token"] == base else 1
        raw_sizes.append(float(amounts[base]))
        prices.append((step, amounts[quote] / max(1, amounts[base])))
        rows_raw.append((step, fill["swapper"], direction, fill["filler"]))

    # Not clipped to the largest size bucket: a request too big for every maker
    # should go unquoted, which `MarketMaker.eligible` already does. Clipping
    # would hand it a fill it would not get.
    sizes = _rescale_sizes(raw_sizes, target_median=40, ceiling=SIZE_CEILING)
    mid = _price_path(prices, total_steps, cfg, (1 << 20) - 1)

    rows = [(step, addr, size, direction)
            for (step, addr, direction, _filler), size in zip(rows_raw, sizes)]
    per_entity = Counter(r[1] for r in rows_raw)
    if min_requests_per_entity > 1:
        keep = {a for a, n in per_entity.items() if n >= min_requests_per_entity}
        rows = [r for r in rows if r[1] in keep]
    winners = Counter(r[3] for r in rows_raw)

    return Tape(mid=mid, rows=rows, source=f"uniswapx:{path.name}",
                meta={"fills": len(fills), "on_pair": len(kept), "used": len(rows),
                      "pair_quote": quote, "pair_base": base,
                      "pairs_available": len(pair_counts),
                      "pair_share": pair_counts[chosen] / max(1, sum(pair_counts.values())),
                      "blocks": span, "step_blocks": step_blocks,
                      "seconds_per_step": step_blocks * SECONDS_PER_BLOCK,
                      "distinct_swappers": len(per_entity),
                      "distinct_fillers": len(winners),
                      "top_filler_share": (winners.most_common(1)[0][1] / len(rows_raw)
                                           if rows_raw else 0.0),
                      "sizes_at_ceiling": sum(1 for v in sizes if v >= SIZE_CEILING),
                      "sizes_over_largest_bucket": sum(1 for v in sizes if v > 400),
                      "checkpoints": checkpoints[:4]})


def load_bybit(path: Path, cfg: SimConfig, *, steps: int | None = None,
               step_ms: int | None = None, start_row: int = 0,
               max_rows: int | None = None) -> Tape:
    """One symbol-day from the Bybit public trading archive.

    Timestamp resolution changes with the era --- 0.1 ms before late 2021 and
    whole seconds after --- so `step_ms` should be at least a second on the
    later files or every trade in a second lands on one step.
    """
    step_ms = step_ms or cfg.step_ms
    total_steps = steps if steps is not None else cfg.steps
    # These files are written newest-first. Reading them in file order silently
    # produces negative step indices, so the sort is not optional.
    trades = []
    with path.open() as handle:
        header = handle.readline().rstrip("\n").split(",")
        col = {name: i for i, name in enumerate(header)}
        for index, line in enumerate(handle):
            if index < start_row:
                continue
            parts = line.rstrip("\n").split(",")
            if len(parts) <= col["price"]:
                continue
            trades.append((float(parts[col["timestamp"]]),
                           float(parts[col["price"]]),
                           float(parts[col["size"]]),
                           # Bybit states the aggressor: a Buy is the taker
                           # lifting the offer, the simulator's direction 0
                           0 if parts[col["side"]] == "Buy" else 1))
            if max_rows and len(trades) >= max_rows:
                break
    if not trades:
        raise ValueError(f"{path} yielded no trades")
    trades.sort(key=lambda t: t[0])
    span_s = total_steps * step_ms / 1000.0
    base = trades[0][0]
    trades = [t for t in trades if t[0] - base <= span_s]
    times = [t[0] for t in trades]
    prices = [t[1] for t in trades]
    sizes = [t[2] for t in trades]
    directions = [t[3] for t in trades]

    steps_of = [min(total_steps, int((t - base) * 1000.0 / step_ms)) for t in times]
    if steps_of and steps_of[0] != 0 or any(a > b for a, b in zip(steps_of, steps_of[1:])):
        # Clamping a negative index to zero would turn a tape read in the wrong
        # order into a tape where every trade happened at once, which still
        # loads, still runs, and reports a market that never existed. The file
        # is newest-first, so this is one missing sort away at all times.
        raise ValueError(
            "trades are not in time order after sorting; the tape's own ordering "
            "changed or the sort was lost")
    tick = statistics.median(prices) / cfg.ref_mid0
    by_step: dict[int, list[float]] = defaultdict(list)
    for step, price in zip(steps_of, prices):
        by_step[step].append(price)
    mid, last = [], cfg.ref_mid0
    for step in range(total_steps + 1):
        if step in by_step:
            last = max(1, int(round(statistics.median(by_step[step]) / tick)))
        mid.append(last)

    lots = _rescale_sizes(sizes, target_median=40, ceiling=SIZE_CEILING)
    rows = [(step, f"taker:{i}", lot, direction)
            for i, (step, lot, direction) in enumerate(zip(steps_of, lots, directions))]
    return Tape(mid=mid, rows=rows, source=f"bybit:{path.name}",
                meta={"trades": len(rows), "step_ms": step_ms,
                      "span_s": times[-1] - times[0],
                      "arrival_per_s": len(rows) / max(1e-9, times[-1] - times[0]),
                      "tick_value": tick,
                      "sizes_over_largest_bucket": sum(1 for v in lots if v > 400),
                      "sizes_at_ceiling": sum(1 for v in lots if v >= SIZE_CEILING)})


def requests_from_tape(cfg: SimConfig, market: TapeMarket, tape: Tape, *,
                       synthetic_entities: int | None = None,
                       wallets_per_entity: int = 1,
                       seed: int = 0) -> tuple[list[Request], SimConfig, dict]:
    """Turn tape rows into `Request`s, and say what the entity column means.

    UniswapX carries a real address per request, so an entity is an address and
    it holds one wallet. That is the least favourable setting for the per-entity
    contribution cap --- with one wallet each there is nothing for the cap to
    collapse --- and saying so is the point: the mechanism is being tested where
    it has the least to work with.

    A Bybit tape has no identities at all, so entities have to be assigned. They
    are dealt round-robin rather than drawn, which keeps the assignment from
    smuggling in a second generated distribution on top of the real arrivals.
    """
    import random

    rng = random.Random(seed)
    addresses = [row[1] for row in tape.rows]
    if synthetic_entities:
        order = list(dict.fromkeys(addresses))
        rng.shuffle(order)
        entity_of = {addr: i % synthetic_entities for i, addr in enumerate(order)}
        n_entities = synthetic_entities
        entity_kind = "assigned round-robin (the tape has no identities)"
    else:
        order = list(dict.fromkeys(addresses))
        entity_of = {addr: i for i, addr in enumerate(order)}
        n_entities = len(order)
        entity_kind = "one entity per observed address"

    requests: list[Request] = []
    for index, (step, addr, size, direction) in enumerate(tape.rows):
        entity = entity_of[addr]
        wallet = entity * wallets_per_entity + (
            rng.randrange(wallets_per_entity) if wallets_per_entity > 1 else 0)
        informed = market.informed_flags[index]
        requests.append(Request(step=step, entity=entity, wallet=wallet, size=size,
                                direction=direction, informed=informed,
                                signal=market.move(step, market.horizon) if informed else 0))

    cfg = dataclasses.replace(cfg, steps=tape.steps, n_entities=n_entities,
                              wallets_per_entity=wallets_per_entity)
    share = sum(1 for r in requests if r.informed) / max(1, len(requests))
    return requests, cfg, {
        "source": tape.source, "requests": len(requests),
        "entities": n_entities, "wallets_per_entity": wallets_per_entity,
        "entity_kind": entity_kind,
        "informed_share_measured": share,
        "agreement_rate_measured": market.agreement_rate,
        "informed_share_estimated": market.informed_share,
        "informed_base_assumed": cfg.informed_base,
        "edge_ticks_measured": market.edge,
        "edge_ticks_assumed": cfg.informed_edge_ticks,
        **tape.meta,
    }
