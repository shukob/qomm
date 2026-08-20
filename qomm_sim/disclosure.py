"""Three market-information disclosure mechanisms compared by the study.

A. none       -- only the counterparties see the firm price.
B. threshold  -- a ZK-style exact statement: at least K independent makers can
                 fill at least V lots inside a band around the reference mid.
                 No noise, but the statement is suppressed when it is false.
C. dp         -- entity-clipped statistics released every window with discrete
                 Laplace noise and a per-entity continual-observation budget.

The DP mechanism follows the entity-level adjacency defined in the proposal:
D and D' differ by removing every request, quote, update and trade made by one
legal entity within the protected period.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field


class PrivacyBudgetExceeded(RuntimeError):
    pass


@dataclass
class EntityAccountant:
    """Continual-observation budget, tracked per protected entity."""

    epsilon_total: float
    spent: float = 0.0
    releases: int = 0

    def spend(self, epsilon: float) -> None:
        if self.spent + epsilon > self.epsilon_total + 1e-12:
            raise PrivacyBudgetExceeded(
                f"budget exhausted: spent={self.spent:.3f} want={epsilon:.3f} cap={self.epsilon_total}")
        self.spent += epsilon
        self.releases += 1

    def can_spend(self, epsilon: float) -> bool:
        return self.spent + epsilon <= self.epsilon_total + 1e-12


def discrete_laplace(epsilon: float, sensitivity: float, rng: random.Random) -> int:
    """Two-sided geometric noise with scale sensitivity/epsilon."""
    if sensitivity <= 0 or epsilon <= 0:
        raise ValueError("sensitivity and epsilon must be positive")
    alpha = math.exp(-epsilon / sensitivity)
    if alpha <= 0.0:
        # scale below one quantum: the mechanism degenerates to no noise, which
        # is the correct limit and avoids log(0) when epsilon is very large
        return 0
    def geom() -> int:
        u = rng.random()
        return int(math.floor(math.log1p(-u) / math.log(alpha)))
    return geom() - geom()


def debias_absolute(observed: float, scale: float) -> float:
    """Recover |S| from a noisy |S + N|, for symmetric noise of this scale.

    Publishing an order-flow imbalance as an absolute value under differential
    privacy biases it upward, and the bias does not shrink the way a reader
    expects noise to: for Laplace noise of scale `b`,

        E|S + N| = |S| + b exp(-|S| / b)

    so perfectly balanced flow still publishes as `b` of imbalance. That is what
    made makers over-estimate informed flow and widen, and why differentially
    private disclosure lost to publishing nothing --- the mechanism was not too
    noisy in a way that showed up as noise, it was skewed in a way that showed
    up as signal.

    Soft thresholding, rather than anything cleverer. Inverting the expectation
    above looks more principled and measures worse: applied to a single draw it
    is a plug-in, not an unbiased estimator, and on the distribution this
    mechanism actually publishes it leaves a mean bias of +361 where this leaves
    -13. Matching the second moment, where `E(S + N)^2 = S^2 + 2b^2` holds
    exactly, also measures worse (+37 mean bias, and a worse RMSE) because the
    truncation at zero reintroduces what the moment identity removed. Measured on
    the real distribution of published windows, mean absolute error is 996 raw,
    949 for the plug-in, 791 for the moment estimator and 698 here.

    Deterministic, so a reader holding the published figure and the published
    noise scale recomputes it exactly; and bounded above by the observation, so
    it never invents imbalance that was not published.

    None of which rescues the mechanism. At the audited epsilon the scale is
    1200 against a median true imbalance of 428, so even the best of these
    estimators has a mean absolute error larger than the quantity. Correcting the
    skew stops the disclosure being actively misleading; it does not make it
    informative.
    """
    if scale <= 0:
        return abs(observed)
    return max(0.0, abs(observed) - scale)


@dataclass(frozen=True)
class WindowObservation:
    """Ground truth for one disclosure window, before any protection."""

    window: int
    start_step: int
    end_step: int
    requests_by_entity: dict[int, int]
    volume_by_entity: dict[int, int]
    signed_volume_by_entity: dict[int, int]
    fills: int
    requests: int
    no_quote: int
    liquidity_lots_in_band: int
    makers_in_band: int
    fills_by_bucket: tuple[int, int, int]
    requests_by_bucket: tuple[int, int, int]


@dataclass(frozen=True)
class Release:
    window: int
    mode: str
    published: bool
    fields: dict
    epsilon_spent: float
    suppressed_reason: str = ""


class DisclosureMechanism:
    name = "none"

    def release(self, obs: WindowObservation, rng: random.Random) -> Release:
        return Release(obs.window, "none", False, {}, 0.0, "arm A publishes nothing")

    def public_signal(self, release: Release) -> tuple[float | None, float]:
        """Return (estimate of informed fraction, variance). Infinite variance = useless."""
        return None, float("inf")


class NoDisclosure(DisclosureMechanism):
    name = "A_none"


class ThresholdDisclosure(DisclosureMechanism):
    """Exact but coarse: one bit per window."""

    name = "B_threshold"

    def __init__(self, min_makers: int = 5, min_lots: int = 800):
        self.min_makers = min_makers
        self.min_lots = min_lots

    def release(self, obs: WindowObservation, rng: random.Random) -> Release:
        holds = obs.makers_in_band >= self.min_makers and obs.liquidity_lots_in_band >= self.min_lots
        if not holds:
            return Release(obs.window, self.name, False, {}, 0.0,
                           "threshold statement not satisfied")
        return Release(obs.window, self.name, True,
                       {"min_makers": self.min_makers, "min_lots": self.min_lots}, 0.0)

    # A satisfied depth statement says the market is not stressed, which shifts
    # the estimate of the informed fraction modestly below the population base.
    # It is one bit, so the residual variance stays wide. Setting the estimate to
    # zero would be wrong: the statement is about depth, not about who is trading.
    CALM_ESTIMATE = 0.24
    CALM_VARIANCE = 0.16

    def public_signal(self, release: Release) -> tuple[float | None, float]:
        if not release.published:
            return None, float("inf")
        return self.CALM_ESTIMATE, self.CALM_VARIANCE


class DPDisclosure(DisclosureMechanism):
    """Entity-clipped statistics with per-window discrete Laplace noise."""

    name = "C_dp"

    def __init__(
        self,
        epsilon_per_window: float,
        request_cap: int,
        volume_cap: int,
        accountants: dict[int, EntityAccountant],
        n_fields: int = 4,
        debias: bool = True,
        signed_sensitivity_factor: float = 1.0,
    ):
        self.epsilon_per_window = epsilon_per_window
        self.request_cap = request_cap
        self.volume_cap = volume_cap
        self.accountants = accountants
        self.n_fields = n_fields
        # On by default now that the skew is understood. Left switchable so the
        # arm that lost to publishing nothing can still be reproduced, since the
        # negative result is only interesting against its own corrected version.
        self.debias = debias
        # Three of the four fields take their sensitivity as one entity's cap,
        # which is what the audited adjacency calls for --- the two worlds differ
        # by removing an entity's whole contribution, and a clipped contribution
        # moves the sum by at most the cap. The signed field alone took twice
        # that, the replace-one figure, which made it the odd one out in this
        # file and doubled its noise for nothing.
        #
        # Lowering it lowers privacy, so it was re-audited rather than argued.
        # Binding the signed field in the two-world game gives a measured leakage
        # lower bound of 0.0000 at the old factor --- over-noised past the point
        # of measurability --- and 0.0940 at this one, against a per-field claim
        # of 0.25 and the request field's own 0.1004. At 0.5 the claim is
        # violated at 0.3415, so the audit has teeth and this is not a vacuous
        # pass. Left switchable so both can be reproduced.
        self.signed_sensitivity_factor = signed_sensitivity_factor

    def release(self, obs: WindowObservation, rng: random.Random) -> Release:
        active = [e for e, c in obs.requests_by_entity.items() if c > 0]
        if any(not self.accountants[e].can_spend(self.epsilon_per_window) for e in active):
            return Release(obs.window, self.name, False, {}, 0.0,
                           "entity privacy budget exhausted")
        for entity in active:
            self.accountants[entity].spend(self.epsilon_per_window)

        eps = self.epsilon_per_window / self.n_fields
        clipped_requests = sum(min(c, self.request_cap) for c in obs.requests_by_entity.values())
        clipped_volume = sum(min(v, self.volume_cap) for v in obs.volume_by_entity.values())
        clipped_signed = sum(
            max(-self.volume_cap, min(v, self.volume_cap))
            for v in obs.signed_volume_by_entity.values()
        )
        clipped_fills = min(obs.fills, sum(min(c, self.request_cap)
                                           for c in obs.requests_by_entity.values()))

        noisy_requests = max(0, clipped_requests + discrete_laplace(eps, self.request_cap, rng))
        noisy_volume = max(0, clipped_volume + discrete_laplace(eps, self.volume_cap, rng))
        signed_sensitivity = self.signed_sensitivity_factor * self.volume_cap
        noisy_signed = clipped_signed + discrete_laplace(eps, signed_sensitivity, rng)
        noisy_fills = max(0, clipped_fills + discrete_laplace(eps, self.request_cap, rng))

        fill_rate = noisy_fills / noisy_requests if noisy_requests > 0 else None
        return Release(
            obs.window, self.name, True,
            {
                "noisy_requests": noisy_requests,
                "noisy_volume": noisy_volume,
                "noisy_signed_volume": noisy_signed,
                "noisy_fills": noisy_fills,
                "fill_rate": fill_rate,
                "exact_requests": clipped_requests,   # kept for error measurement only
                "exact_volume": clipped_volume,
                "exact_signed_volume": clipped_signed,
                "exact_fills": clipped_fills,
                "request_cap": self.request_cap,
                "volume_cap": self.volume_cap,
                "noise_scale_requests": self.request_cap / eps,
                "noise_scale_signed": signed_sensitivity / eps,
                "debiased": self.debias,
            },
            self.epsilon_per_window,
        )

    def public_signal(self, release: Release) -> tuple[float | None, float]:
        """Signed order-flow imbalance is the public proxy for informed flow."""
        if not release.published:
            return None, float("inf")
        volume = release.fields["noisy_volume"]
        if volume <= 0:
            return None, float("inf")
        signed = release.fields["noisy_signed_volume"]
        if release.fields.get("debiased", False):
            magnitude = debias_absolute(signed, release.fields["noise_scale_signed"])
        else:
            magnitude = abs(signed)
        imbalance = magnitude / max(1, volume)
        estimate = min(0.95, max(0.0, imbalance))
        # variance = sampling variance + DP noise contribution
        noise_sd = release.fields["noise_scale_signed"] * math.sqrt(2.0)
        var = 0.02 + (noise_sd / max(1, volume)) ** 2
        return estimate, var
