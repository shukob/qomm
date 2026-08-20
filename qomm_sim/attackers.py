"""The five adversaries the proposal requires, each given only what its arm leaks.

Reporting rule taken from the proposal: never report raw accuracy alone. In a
data set where most (entity, window) pairs are inactive, always answering
"inactive" already scores well. Every attacker therefore reports AUC and the
advantage over the base rate, and the probing attackers report how many probes
were needed.

The headline privacy metric is deliberately narrow:

    "did entity e make a request in window w, given that entity e settled
     nothing in window w"

because that is exactly the guarantee the proposal claims for the query-oblivious
design: secrecy for what does *not* settle. Executed trades stay visible on
chain in every arm at phase 1, so an evaluation that mixed them in would
flatter the design.
"""

from __future__ import annotations

import math
import random
import statistics
from dataclasses import dataclass

from .engine import ArmResult
from .market import SimConfig, size_bucket


def auc(scores: list[float], labels: list[int]) -> float | None:
    """Rank-based AUC, ties averaged."""
    pairs = sorted(zip(scores, labels))
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return None
    rank = 1
    rank_sum = 0.0
    index = 0
    while index < len(pairs):
        stop = index
        while stop + 1 < len(pairs) and pairs[stop + 1][0] == pairs[index][0]:
            stop += 1
        avg_rank = (rank + (rank + (stop - index))) / 2.0
        for k in range(index, stop + 1):
            if pairs[k][1] == 1:
                rank_sum += avg_rank
        rank += stop - index + 1
        index = stop + 1
    return (rank_sum - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def tpr_at_fpr(scores: list[float], labels: list[int], target_fpr: float = 0.05) -> float | None:
    """Detection rate at a fixed false-positive rate.

    Ties must be resolved by interpolation, not by input order. A threshold
    cannot separate examples that share a score, so counting the positives in a
    tie group first would report a detection rate no real attacker can reach.
    That matters here because the query-oblivious arms produce entirely tied
    scores, and order-dependent counting would make them look leakier than they
    are.
    """
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return None
    order = sorted(zip(scores, labels), key=lambda p: -p[0])
    tp = fp = 0
    best = 0.0
    index = 0
    while index < len(order):
        stop = index
        while stop + 1 < len(order) and order[stop + 1][0] == order[index][0]:
            stop += 1
        group_pos = sum(1 for k in range(index, stop + 1) if order[k][1] == 1)
        group_neg = (stop - index + 1) - group_pos
        if fp + group_neg <= target_fpr * n_neg:
            tp += group_pos
            fp += group_neg
            best = max(best, tp / n_pos)
        else:
            # admit the fraction of the tie group the budget allows
            room = target_fpr * n_neg - fp
            if group_neg > 0 and room > 0:
                share = room / group_neg
                best = max(best, (tp + share * group_pos) / n_pos)
            break
        index = stop + 1
    return best


@dataclass
class AttackReport:
    name: str
    target: str
    auc: float | None
    tpr_at_5pct_fpr: float | None
    base_rate: float
    advantage: float | None
    n_examples: int
    extra: dict

    def as_dict(self) -> dict:
        return {
            "attacker": self.name, "target": self.target, "auc": self.auc,
            "tpr_at_5pct_fpr": self.tpr_at_5pct_fpr, "base_rate": self.base_rate,
            "advantage_over_prior": self.advantage, "n": self.n_examples, **self.extra,
        }


class Attack:
    """One adversary, scored the same way as every other.

    Five of the six attackers share a shape: build a score and a label for each
    (entity, window) pair the design claims to protect, then report AUC, the
    detection rate at a fixed false-positive rate, and the advantage over the
    base rate. That reporting was copied into each of them, so a change to how
    detection is reported had to be made five times and could be made four.

    A subclass supplies `score_population`; everything after it is here.
    """

    name = "attack"
    target = "target"

    def score_population(self, result: ArmResult, cfg: SimConfig
                         ) -> tuple[list[float], list[int]]:
        """Return (scores, labels), one entry per example this attacker sees."""
        raise NotImplementedError

    def extra(self, result: ArmResult, cfg: SimConfig) -> dict:
        """Anything this attacker reports beyond the shared statistics."""
        return {}

    def run(self, result: ArmResult, cfg: SimConfig) -> AttackReport:
        scores, labels = self.score_population(result, cfg)
        base = sum(labels) / len(labels) if labels else 0.0
        value = auc(scores, labels)
        return AttackReport(
            self.name, self.target, value, tpr_at_fpr(scores, labels), base,
            abs(value - 0.5) * 2 if value is not None else None, len(labels),
            self.extra(result, cfg))


class UnsettledRequestAttack(Attack):
    """Shared by the two attackers that ask the design's own question.

    The population is deliberately narrow --- only (entity, window) pairs where
    the entity settled nothing --- because that is exactly what the design claims
    to hide. Including settled pairs would flatter it, since settlements are
    visible in every arm.
    """

    target = "unsettled_request_existence"

    def window_score(self, result: ArmResult, cfg: SimConfig) -> dict[int, float]:
        return {}

    def pair_score(self, key: tuple[int, int]) -> float:
        return 0.0

    def prepare(self, result: ArmResult, cfg: SimConfig) -> None:
        pass

    def score_population(self, result: ArmResult, cfg: SimConfig
                         ) -> tuple[list[float], list[int]]:
        self.prepare(result, cfg)
        requested, settled = _ground_truth(result, cfg)
        by_window = self.window_score(result, cfg)
        n_windows = max(1, cfg.steps // cfg.window_steps)
        scores, labels = [], []
        for entity in range(cfg.n_entities):
            for window in range(n_windows):
                key = (entity, window)
                if settled.get(key):
                    continue
                scores.append(self.pair_score(key) + by_window.get(window, 0.0))
                labels.append(1 if requested.get(key) else 0)
        return scores, labels


def _window_of(step: int, cfg: SimConfig) -> int:
    return step // cfg.window_steps


def _ground_truth(result: ArmResult, cfg: SimConfig) -> tuple[dict, dict]:
    """(entity, window) -> requested?, and (entity, window) -> settled?"""
    requested: dict[tuple[int, int], int] = {}
    settled: dict[tuple[int, int], int] = {}
    for row in result.truth:
        key = (row["entity"], _window_of(row["step"], cfg))
        requested[key] = 1
        if row["executed"]:
            settled[key] = 1
    return requested, settled


def _linked_wallets(cfg: SimConfig, rho: float, seed: int = 0) -> set[int]:
    """Wallets whose controlling entity the attacker has already de-anonymised.

    Drawn at random rather than taken at a fixed stride. The stride version was
    wrong in three ways that all pushed the same direction --- towards an
    attacker stronger than the number claimed.

    It quantised the fraction, because the stride is `round(1/rho)`: asking for
    0.75 and for 1.0 both gave stride 1, so those were the same experiment
    reported as two points.

    It never returned the empty set. At `rho = 0` the stride was set past the
    end of the range, and `range(0, n, n+1)` still yields wallet 0, so an
    attacker with no linkage at all knew one wallet.

    And it correlated with the numbering, which is entity-major: wallet
    `e * wallets_per_entity + j` belongs to entity `e`. Any stride below
    `wallets_per_entity` hits every entity, so `rho = 0.5` over 24 firms holding
    three wallets each de-anonymised half the wallets but *all* of the firms ---
    and a stride sharing a factor with `wallets_per_entity` picks the same slot
    inside every one of them. The attack keys on the entity, so entity coverage
    is what it actually spends.

    Sampling is seeded, so a run reproduces, and the seed varies with the
    experiment's so that averaging over seeds also averages over which wallets
    the attacker happens to hold.
    """
    n_wallets = cfg.n_entities * cfg.wallets_per_entity
    if rho <= 0:
        return set()
    if rho >= 1:
        return set(range(n_wallets))
    return set(random.Random(seed).sample(range(n_wallets), round(rho * n_wallets)))


class PassiveObserver(UnsettledRequestAttack):
    """Attacker 1: whatever the protocol leaks at request time, plus releases.

    Two channels feed one score. The direct channel is a request or settlement
    seen from a wallet the attacker has already de-anonymised; the aggregate
    channel is how surprising the published count for that window was. The
    aggregate is weighted a thousandth of the direct one because it cannot
    identify anybody by itself --- it only breaks ties.
    """

    name = "A1_passive_observer"

    def __init__(self, linkage_rho: float = 0.5, seed: int | None = None):
        self.linkage_rho = linkage_rho
        self.seed = seed
        self.linked: set[int] = set()
        self.seen: set[tuple[int, int]] = set()

    def prepare(self, result: ArmResult, cfg: SimConfig) -> None:
        self.linked = _linked_wallets(
            cfg, self.linkage_rho, cfg.seed if self.seed is None else self.seed)
        self.seen = set()
        for obs in result.observations:
            if obs.wallet in self.linked:
                self.seen.add((obs.entity, _window_of(obs.step, cfg)))
        # settlements are on chain in every arm
        for stl in result.settlements:
            if stl.wallet in self.linked:
                self.seen.add((stl.entity, _window_of(stl.step, cfg)))

    def pair_score(self, key: tuple[int, int]) -> float:
        return 1.0 if key in self.seen else 0.0

    def window_score(self, result: ArmResult, cfg: SimConfig) -> dict[int, float]:
        out: dict[int, float] = {}
        for release in result.releases:
            if not release.published:
                continue
            if release.mode == "C_dp":
                noisy = release.fields["noisy_requests"]
                scale = release.fields["noise_scale_requests"]
                out[release.window] = 0.001 * (noisy / max(1.0, scale))
            elif release.mode == "B_threshold":
                out[release.window] = 0.001 * 0.5
        return out

    def extra(self, result: ArmResult, cfg: SimConfig) -> dict:
        return {"linkage_rho": self.linkage_rho,
                "wallets_linked": len(self.linked),
                "entities_covered": len({w // cfg.wallets_per_entity
                                         for w in self.linked})}


def passive_observer(result: ArmResult, cfg: SimConfig, linkage_rho: float = 0.5,
                     seed: int | None = None) -> AttackReport:
    return PassiveObserver(linkage_rho, seed).run(result, cfg)


class WindowShiftObserver(UnsettledRequestAttack):
    """Attacker 2: the difference between adjacent published windows.

    Continual observation is where a per-window budget is supposed to bite, so
    the attack that differences consecutive releases is the one that tests it.
    """

    name = "A2_window_shift"

    def window_score(self, result: ArmResult, cfg: SimConfig) -> dict[int, float]:
        n_windows = max(1, cfg.steps // cfg.window_steps)
        published = {r.window: r for r in result.releases if r.published}
        delta: dict[int, float] = {}
        previous = None
        for window in range(n_windows):
            release = published.get(window)
            if release is None or release.mode != "C_dp":
                continue
            current = release.fields["noisy_requests"]
            if previous is not None:
                delta[window] = ((current - previous)
                                 / max(1.0, release.fields["noise_scale_requests"]))
            previous = current
        return delta


def window_shift_observer(result: ArmResult, cfg: SimConfig) -> AttackReport:
    return WindowShiftObserver().run(result, cfg)


def probing_entity(result: ArmResult, cfg: SimConfig, probe_budget: int) -> AttackReport:
    """Attacker 3: reconstruct aggregate maker inventory from firm prices.

    Query-obliviousness does not stop this attack: a firm price is exactly what
    the protocol is designed to return. Only entity-level rate limits do.
    """
    available = [p for p in result.probe_results
                 if p.best_ask is not None and p.best_bid is not None]
    # spend the allowance evenly over the horizon; a prefix would confound the
    # budget with the time period observed
    if probe_budget >= len(available):
        rows = available
    else:
        stride = len(available) / probe_budget
        rows = [available[int(k * stride)] for k in range(probe_budget)]
    if len(rows) < 4:
        # four points is the floor at which a correlation means anything
        return AttackReport("A3_probing_entity", "maker_inventory", None, None, 0.0,
                            None, len(rows), {"probe_budget": probe_budget,
                                              "note": "insufficient probes"})

    # The midpoint of a two-sided quote cancels the half spread, so what is left
    # is the inventory skew the maker applied.
    best_skew = [0.5 * (p.best_ask + p.best_bid) - p.ref_mid for p in rows]
    net_inventory = [float(p.true_net_inventory) for p in rows]
    corr_best = _pearson(best_skew, net_inventory)

    # A plain protocol answers per maker, so the same estimator applies per maker.
    per_mm_corr = None
    if rows[0].per_mm_quotes is not None:
        per_mm: list[float] = []
        for mm_id in rows[0].per_mm_quotes:
            series = [(0.5 * (q[0] + q[1]) - p.ref_mid, p.per_mm_inventory[mm_id])
                      for p in rows
                      if p.per_mm_quotes and (q := p.per_mm_quotes.get(mm_id)) is not None]
            if len(series) < 4:
                continue
            value = _pearson([a for a, _ in series], [float(b) for _, b in series])
            if value is not None:
                per_mm.append(abs(value))
        per_mm_corr = statistics.fmean(per_mm) if per_mm else None

    return AttackReport(
        "A3_probing_entity", "maker_inventory", None, None, 0.0, None, len(rows),
        {
            "probe_budget": probe_budget,
            "net_inventory_corr_from_best_quote": abs(corr_best) if corr_best is not None else None,
            "own_inventory_corr_from_per_mm_quotes": per_mm_corr,
        },
    )


def pretrade_attributes(result: ArmResult, cfg: SimConfig) -> AttackReport:
    """Direction and size-bucket recovery for requests that never executed.

    This is the metric that separates plain RFQ, RFM and RFS from each other.
    RFM already hides direction and RFS already hides size without any
    cryptography, so those savings must not be credited to the MPC design.
    An attacker that never sees the request has to fall back on the population
    prior, which is the number reported for the query-oblivious arms.
    """
    unsettled = [row for row in result.truth if not row["executed"]]
    if not unsettled:
        return AttackReport("A1b_pretrade_attributes", "direction_and_size", None, None,
                            0.0, None, 0, {})
    seen = {(o.step, o.wallet): o for o in result.observations}

    # population priors an uninformed attacker would use
    dir_counts = [0, 0]
    bucket_counts = [0, 0, 0]
    for row in unsettled:
        dir_counts[row["direction"]] += 1
        bucket_counts[size_bucket(row["size"])] += 1
    prior_dir = max(dir_counts) / len(unsettled)
    prior_bucket = max(bucket_counts) / len(unsettled)
    majority_dir = dir_counts.index(max(dir_counts))
    majority_bucket = bucket_counts.index(max(bucket_counts))

    dir_hits = bucket_hits = 0
    for row in unsettled:
        obs = seen.get((row["step"], row["wallet"]))
        if obs is not None and obs.direction is not None:
            dir_hits += 1 if obs.direction == row["direction"] else 0
        else:
            dir_hits += 1 if majority_dir == row["direction"] else 0
        if obs is not None and obs.size is not None:
            bucket_hits += 1 if size_bucket(obs.size) == size_bucket(row["size"]) else 0
        else:
            bucket_hits += 1 if majority_bucket == size_bucket(row["size"]) else 0

    return AttackReport(
        "A1b_pretrade_attributes", "direction_and_size", None, None, prior_dir, None,
        len(unsettled),
        {
            "direction_accuracy": dir_hits / len(unsettled),
            "direction_prior": prior_dir,
            "size_bucket_accuracy": bucket_hits / len(unsettled),
            "size_bucket_prior": prior_bucket,
        },
    )


def probe_cost_curve(result: ArmResult, cfg: SimConfig,
                     budgets: tuple[int, ...] = (4, 6, 8, 12, 16, 24, 32, 64, 128, 256)) -> dict:
    """How much probing does the inventory attack actually need?"""
    curve = {}
    for budget in budgets:
        report = probing_entity(result, cfg, budget)
        curve[budget] = {
            "net": report.extra.get("net_inventory_corr_from_best_quote"),
            "per_mm": report.extra.get("own_inventory_corr_from_per_mm_quotes"),
        }
    return curve


def _probes_needed(curve: dict, key: str, target: float) -> int | None:
    for budget in sorted(curve):
        value = curve[budget][key]
        if value is not None and value >= target:
            return budget
    return None


def colluding_wallets(
    result: ArmResult, cfg: SimConfig, wallet_limit: int, entity_limit: int
) -> AttackReport:
    """Attacker 4: a wallet-level cap scales with wallet count; an entity cap does not."""
    n_windows = max(1, cfg.steps // cfg.window_steps)
    wallet_capped = wallet_limit * cfg.wallets_per_entity * n_windows
    entity_capped = entity_limit * n_windows
    curve = probe_cost_curve(result, cfg)
    under_wallet = probing_entity(result, cfg, wallet_capped)
    under_entity = probing_entity(result, cfg, entity_capped)
    return AttackReport(
        "A4_colluding_wallets", "maker_inventory", None, None, 0.0, None,
        min(len(result.probe_results), wallet_capped),
        {
            "probes_under_wallet_limit": wallet_capped,
            "probes_under_entity_limit": entity_capped,
            "corr_under_wallet_limit": under_wallet.extra.get("net_inventory_corr_from_best_quote"),
            "corr_under_entity_limit": under_entity.extra.get("net_inventory_corr_from_best_quote"),
            "probe_cost_curve": curve,
            "probes_needed_net_corr_0.8": _probes_needed(curve, "net", 0.8),
            "probes_needed_per_mm_corr_0.8": _probes_needed(curve, "per_mm", 0.8),
        },
    )


class ExternalInfoObserver(Attack):
    """Attacker 5: was this settled trade informed?

    Settlements are visible in every arm, so this attack is unchanged by hiding
    requests --- which is the reason to report it. It marks the boundary of what
    the design claims.
    """

    name = "A5_external_info"
    target = "settled_trade_was_informed"

    def __init__(self, market):
        self.market = market

    def score_population(self, result: ArmResult, cfg: SimConfig
                         ) -> tuple[list[float], list[int]]:
        informed = {(row["step"], row["wallet"]): row["informed"] for row in result.truth}
        scores, labels = [], []
        for stl in result.settlements:
            future = (self.market.mid[min(stl.step + 20, cfg.steps)]
                      - self.market.mid[stl.step])
            # a buy just before a rise looks informed
            signed_move = future if stl.direction == 0 else -future
            scores.append(float(signed_move))
            labels.append(1 if informed.get((stl.step, stl.wallet)) else 0)
        return scores, labels


def external_info_observer(result: ArmResult, cfg: SimConfig, market) -> AttackReport:
    return ExternalInfoObserver(market).run(result, cfg)


def _pearson(a: list[float], b: list[float]) -> float | None:
    n = min(len(a), len(b))
    if n < 3:
        return None
    a, b = a[:n], b[:n]
    ma, mb = statistics.fmean(a), statistics.fmean(b)
    num = sum((x - ma) * (y - mb) for x, y in zip(a, b))
    da = math.sqrt(sum((x - ma) ** 2 for x in a))
    db = math.sqrt(sum((y - mb) ** 2 for y in b))
    if da == 0 or db == 0:
        return None
    return num / (da * db)
